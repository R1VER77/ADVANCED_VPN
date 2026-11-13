//! The option E mix lane's daemon (EXPERIMENTAL, gate G2 of
//! crates/avpn-mix-lane/CUTOVER_KATZENPOST.md: lab use only; `avpn mix` runs Katzenpost).
//!
//! One binary, four roles:
//! - `keygen`: a mix's ML-KEM-768 + X25519 keys (OS CSPRNG), secret kept 0600.
//! - `mix`: accept cells, hold each an Exp(μ) delay (crates/avpn-mix-lane `MixNode`),
//!   forward to the next hop. Invalid cells occupy a delay slot and vanish (§1.2).
//! - `provider`: a mix that is also the last hop: keeps mailboxes, answers pulls, and
//!   (with `--service`) runs the fetch service behind a pool of single-use reply blocks.
//! - `client`: real-or-drop cells and loops at Poisson rates whatever it has to say; an
//!   HTTP proxy on 127.0.0.1 turns `HEAD https://site/` requests into mixnet requests.
//!
//! Why a SURB pool: option E seals a forward cell's payload under a key derived from
//! every hop's secret, so only its sender can read it. A third party (the fetch service)
//! is therefore reached the Mixminion way: it publishes single-use reply blocks to its
//! own mailboxes; a client sends its request through one, with its own reply block for
//! the answer. Everyone fetches the whole pool, so the service cannot tell who used which.
use anyhow::{Context, Result, bail, ensure};
use avpn_mix_lane::{
    mix::{MixConfig, MixNode, Outbound, ScheduleRng, TrafficClass, frame_for_wire},
    sphinx::{
        CELL_SIZE, MixKeys, MixSecret, SphinxRng, build_cell, build_surb, mix_keypair,
        open_payload, open_surb_reply, surb_reply_cell,
    },
};
use clap::{Parser, Subcommand};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::oneshot,
};

const FRAME_LEN: usize = 4 + 4096;
const PULL_MAGIC: &[u8; 8] = b"AVPNPULL";
/// Cells addressed here are dropped by the provider: the client's drop cover.
const DROP_MAILBOX: [u8; 16] = [0; 16];
const HOPS: usize = 3;
const REPLY_LIMIT: usize = 2400;

#[derive(Parser)]
#[command(about = "Option E mix lane daemon (experimental, lab only)")]
struct Args {
    /// Required: this daemon is experimental (unsigned directory, unreviewed §2.3).
    #[arg(long)]
    experimental: bool,
    #[command(subcommand)]
    role: Role,
}

#[derive(Subcommand)]
enum Role {
    /// Generate a mix's keys into DIR (secret.json 0600, public.json).
    Keygen {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        addr: SocketAddr,
        /// mix | provider
        #[arg(long)]
        role: String,
    },
    /// Run a mix or a provider.
    Mix {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        directory: PathBuf,
        #[arg(long, default_value_t = 200)]
        mean_delay_ms: u64,
        /// Provider only: run the fetch service and publish its reply-block pool here.
        #[arg(long)]
        service_pool: Option<PathBuf>,
        #[arg(long, default_value_t = 4000)]
        pool_size: usize,
        /// Service: also fetch from sites that offer only a classical TLS 1.3 key exchange
        /// (by default only a hybrid post-quantum group, X25519MLKEM768, is accepted).
        #[arg(long)]
        allow_classical_tls13: bool,
    },
    /// Run a client with an HTTP proxy on `--listen`.
    Client {
        #[arg(long)]
        directory: PathBuf,
        /// The provider holding this client's mailbox.
        #[arg(long)]
        provider: String,
        #[arg(long)]
        pool: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: SocketAddr,
        /// Real-or-drop cells per second (Poisson), and loops per second.
        #[arg(long, default_value_t = 1.0)]
        lambda_p: f64,
        #[arg(long, default_value_t = 0.5)]
        lambda_l: f64,
        #[arg(long, default_value_t = 1000)]
        pull_ms: u64,
    },
}

/// The OS-seeded CSPRNG behind the crate's SWAPPABLE RNG traits.
struct Csprng;
impl SphinxRng for Csprng {
    fn fill(&mut self, buf: &mut [u8]) {
        rand::rng().fill_bytes(buf);
    }
}
impl ScheduleRng for Csprng {
    fn next_unit(&mut self) -> f64 {
        rand::rng().random::<f64>()
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct PublicEntry {
    id: String,
    addr: SocketAddr,
    role: String,
    mlkem_ek: String,
    x25519_pk: String,
}
#[derive(Serialize, Deserialize)]
struct SecretFile {
    id: String,
    mlkem_dk: String,
    x25519_sk: String,
}
#[derive(Deserialize)]
struct Directory {
    mixes: Vec<PublicEntry>,
}

struct Node {
    keys: MixKeys,
    addr: SocketAddr,
    role: String,
}

fn id16(s: &str) -> Result<[u8; 16]> {
    hex::decode(s)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("bad id"))
}

fn load_directory(path: &Path) -> Result<Vec<Node>> {
    let d: Directory = serde_json::from_slice(&std::fs::read(path)?)?;
    d.mixes
        .into_iter()
        .map(|e| {
            Ok(Node {
                keys: MixKeys {
                    id: id16(&e.id)?,
                    mlkem_ek: hex::decode(&e.mlkem_ek)?,
                    x25519_pk: hex::decode(&e.x25519_pk)?
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("bad x25519 key"))?,
                },
                addr: e.addr,
                role: e.role,
            })
        })
        .collect()
}

fn keygen(dir: &Path, addr: SocketAddr, role: &str) -> Result<()> {
    ensure!(
        matches!(role, "mix" | "provider"),
        "role is mix or provider"
    );
    std::fs::create_dir_all(dir)?;
    let mut r = Csprng;
    let (mut d, mut z, mut x, mut id) = ([0u8; 32], [0u8; 32], [0u8; 32], [0u8; 16]);
    r.fill(&mut d);
    r.fill(&mut z);
    r.fill(&mut x);
    r.fill(&mut id);
    let (keys, secret) = mix_keypair(&d, &z, x, id);
    let secret_file = SecretFile {
        id: hex::encode(id),
        mlkem_dk: hex::encode(&secret.mlkem_dk),
        x25519_sk: hex::encode(secret.x25519_sk),
    };
    let path = dir.join("secret.json");
    std::fs::write(&path, serde_json::to_vec(&secret_file)?)?;
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    let public = PublicEntry {
        id: hex::encode(id),
        addr,
        role: role.into(),
        mlkem_ek: hex::encode(&keys.mlkem_ek),
        x25519_pk: hex::encode(keys.x25519_pk),
    };
    std::fs::write(dir.join("public.json"), serde_json::to_vec(&public)?)?;
    Ok(())
}

fn now_ms(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

fn unframe(buf: &[u8]) -> Option<[u8; CELL_SIZE]> {
    if buf.len() != FRAME_LEN {
        return None;
    }
    let len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    if len != CELL_SIZE {
        return None;
    }
    buf[4..4 + CELL_SIZE].try_into().ok()
}

/// One entry of the service's published reply-block pool.
#[derive(Serialize, Deserialize, Clone)]
struct PoolEntry {
    first: String,
    surb: String,
}

/// A reply block the service holds the secrets for, by its mailbox.
struct Held {
    reply_secret: [u8; 32],
    path_secrets: Vec<[u8; 32]>,
}

/// A request a client sends through a service reply block, in binary so the client's
/// own 1,428-byte reply block fits: method(1) || first hop(16) || surb_len(2) || surb || url.
struct Request {
    method: String,
    url: String,
    surb: Vec<u8>,
    first: [u8; 16],
}

impl Request {
    fn encode(&self) -> Vec<u8> {
        let mut out = vec![u8::from(self.method == "GET")];
        out.extend_from_slice(&self.first);
        out.extend_from_slice(&(self.surb.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.surb);
        out.extend_from_slice(self.url.as_bytes());
        out
    }

    fn decode(b: &[u8]) -> Option<Self> {
        let method = if *b.first()? == 1 { "GET" } else { "HEAD" };
        let first: [u8; 16] = b.get(1..17)?.try_into().ok()?;
        let len = u16::from_be_bytes(b.get(17..19)?.try_into().ok()?) as usize;
        let surb = b.get(19..19 + len)?.to_vec();
        let url = std::str::from_utf8(b.get(19 + len..)?).ok()?.to_string();
        Some(Self {
            method: method.into(),
            url,
            surb,
            first,
        })
    }
}

fn random_path(nodes: &[Node], last: &MixKeys) -> Vec<MixKeys> {
    let mixes: Vec<&Node> = nodes.iter().filter(|n| n.role == "mix").collect();
    let mut rng = rand::rng();
    let mut path = Vec::with_capacity(HOPS);
    let a = rng.random_range(0..mixes.len());
    let mut b = rng.random_range(0..mixes.len());
    if mixes.len() > 1 {
        while b == a {
            b = rng.random_range(0..mixes.len());
        }
    }
    path.push(mixes[a].keys.clone());
    path.push(mixes[b].keys.clone());
    path.push(last.clone());
    path
}

/// Minimal HTTPS client for the fetch service: HEAD or GET, status line and headers
/// (and a GET body) truncated to fit one reply. TLS 1.3 only, X25519MLKEM768 offered
/// first; with `pq_only`, a site that negotiates a classical group is refused (526), and
/// a site without TLS 1.3 is refused too (525): never a classical-only protocol.
async fn fetch(method: &str, url: &str, pq_only: bool) -> String {
    let attempt = async {
        let rest = url.strip_prefix("https://").context("https URLs only")?;
        let (host, path) = match rest.split_once('/') {
            Some((h, p)) => (h.to_string(), format!("/{p}")),
            None => (rest.to_string(), "/".into()),
        };
        ensure!(
            !host.is_empty()
                && host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'),
            "bad host"
        );
        let addr = tokio::net::lookup_host((host.as_str(), 443))
            .await?
            .find(|a| a.is_ipv4())
            .context("no address")?;
        let ip = addr.ip();
        ensure!(
            match ip {
                std::net::IpAddr::V4(v4) =>
                    !(v4.is_private()
                        || v4.is_loopback()
                        || v4.is_link_local()
                        || v4.is_unspecified()),
                _ => false,
            },
            "non-global address"
        );
        let tcp = tokio::time::timeout(Duration::from_secs(15), TcpStream::connect(addr)).await??;
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let name = rustls::pki_types::ServerName::try_from(host.clone())?;
        let mut tls =
            tokio::time::timeout(Duration::from_secs(15), connector.connect(name, tcp)).await??;
        let hybrid = matches!(
            tls.get_ref()
                .1
                .negotiated_key_exchange_group()
                .map(|g| g.name()),
            Some(
                rustls::NamedGroup::X25519MLKEM768
                    | rustls::NamedGroup::secp256r1MLKEM768
                    | rustls::NamedGroup::MLKEM768
                    | rustls::NamedGroup::MLKEM1024
            )
        );
        if pq_only && !hybrid {
            return Ok("HTTP/1.1 526 Classical Key Exchange Refused\r\n\r\n".to_string());
        }
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        tls.write_all(req.as_bytes()).await?;
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        while out.len() < REPLY_LIMIT {
            // Many servers close without TLS close_notify (an "unexpected EOF"): what was
            // read before that is still the answer, so stop reading rather than fail.
            match tokio::time::timeout(Duration::from_secs(15), tls.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => out.extend_from_slice(&buf[..n]),
                _ => break,
            }
        }
        out.truncate(REPLY_LIMIT);
        Ok::<String, anyhow::Error>(String::from_utf8_lossy(&out).into_owned())
    };
    match attempt.await {
        Ok(s) if s.starts_with("HTTP/") => s,
        other => {
            // The reason only (never the URL): lab diagnostics.
            let reason = match other {
                Err(e) => format!("{e:#}"),
                Ok(s) => format!("not HTTP ({} bytes)", s.len()),
            };
            eprintln!("fetch failed: {reason}");
            if reason.contains("ProtocolVersion") {
                // The site offers no TLS 1.3: refused, never downgraded.
                "HTTP/1.1 525 TLS 1.3 Unavailable\r\n\r\n".into()
            } else {
                "HTTP/1.1 502 Bad Gateway\r\n\r\n".into()
            }
        }
    }
}

async fn run_mix(
    dir: &Path,
    directory: &Path,
    mean_delay_ms: u64,
    service_pool: Option<PathBuf>,
    pool_size: usize,
    pq_only: bool,
) -> Result<()> {
    let secret: SecretFile = serde_json::from_slice(&std::fs::read(dir.join("secret.json"))?)?;
    let me: PublicEntry = serde_json::from_slice(&std::fs::read(dir.join("public.json"))?)?;
    let nodes = Arc::new(load_directory(directory)?);
    let id = id16(&secret.id)?;
    let sk = MixSecret {
        mlkem_dk: hex::decode(&secret.mlkem_dk)?,
        x25519_sk: hex::decode(&secret.x25519_sk)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad x25519 secret"))?,
    };
    let cfg = MixConfig {
        mean_delay_ms,
        ..MixConfig::default()
    };
    let node = Arc::new(Mutex::new(MixNode::new(id, sk, cfg)));
    let sock = Arc::new(UdpSocket::bind(me.addr).await?);
    let addr_of: HashMap<[u8; 16], SocketAddr> =
        nodes.iter().map(|n| (n.keys.id, n.addr)).collect();
    let start = Instant::now();
    ensure!(
        service_pool.is_none() || me.role == "provider",
        "only a provider runs the service"
    );

    // The service: a pool of reply blocks to this provider's own mailboxes.
    let held: Arc<Mutex<HashMap<[u8; 16], Held>>> = Arc::default();
    if let Some(pool_path) = &service_pool {
        let my_keys = nodes
            .iter()
            .find(|n| n.keys.id == id)
            .context("provider not in directory")?
            .keys
            .clone();
        let mut entries = Vec::with_capacity(pool_size);
        let mut h = held.lock().unwrap();
        for _ in 0..pool_size {
            let mut mailbox = [0u8; 16];
            Csprng.fill(&mut mailbox);
            let path = random_path(&nodes, &my_keys);
            let surb =
                build_surb(&path, &mailbox, &mut Csprng).map_err(|e| anyhow::anyhow!("{e:?}"))?;
            entries.push(PoolEntry {
                first: hex::encode(path[0].id),
                surb: hex::encode(&surb.bytes),
            });
            h.insert(
                mailbox,
                Held {
                    reply_secret: surb.reply_secret,
                    path_secrets: surb.path_secrets,
                },
            );
        }
        drop(h);
        let tmp = pool_path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(&entries)?)?;
        std::fs::rename(tmp, pool_path)?;
    }

    // Ingress: cells and (providers) mailbox pulls.
    {
        let (node, sock) = (node.clone(), sock.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    continue;
                };
                if n == 8 + 16 && &buf[..8] == PULL_MAGIC {
                    let owner: [u8; 16] = buf[8..24].try_into().unwrap();
                    if owner == DROP_MAILBOX {
                        continue;
                    }
                    let cells = node.lock().unwrap().pull_mailbox(&owner);
                    for cell in cells {
                        let _ = sock.send_to(&frame_for_wire(&cell), peer).await;
                    }
                    continue;
                }
                if let Some(cell) = unframe(&buf[..n]) {
                    let now = now_ms(start);
                    let _ =
                        node.lock()
                            .unwrap()
                            .accept(&cell, TrafficClass::Data, now, &mut Csprng);
                }
            }
        });
    }
    // Egress: expired delay slots forward; the service answers its mailboxes.
    let mut tick = tokio::time::interval(Duration::from_millis(5));
    let mut stats_at = Instant::now();
    loop {
        tick.tick().await;
        let out = node.lock().unwrap().drain(now_ms(start));
        for o in out {
            if let Outbound::Forward { next_id, cell } = o
                && let Some(addr) = addr_of.get(&next_id)
            {
                let _ = sock.send_to(&frame_for_wire(&cell[..]), *addr).await;
            }
        }
        node.lock().unwrap().pull_mailbox(&DROP_MAILBOX);
        if service_pool.is_some() {
            let ready: Vec<([u8; 16], Vec<[u8; CELL_SIZE]>)> = {
                let h = held.lock().unwrap();
                let mut n = node.lock().unwrap();
                h.keys()
                    .filter_map(|mb| {
                        let cells = n.pull_mailbox(mb);
                        (!cells.is_empty()).then_some((*mb, cells))
                    })
                    .collect()
            };
            for (mailbox, cells) in ready {
                let Some(hb) = held.lock().unwrap().remove(&mailbox) else {
                    continue;
                };
                for cell in cells {
                    let Some(msg) = open_surb_reply(&hb.reply_secret, &hb.path_secrets, &cell)
                    else {
                        continue;
                    };
                    let Some(req) = Request::decode(&msg) else {
                        continue;
                    };
                    let (sock, addr_of) = (sock.clone(), addr_of.clone());
                    tokio::spawn(async move {
                        let method = if req.method == "GET" { "GET" } else { "HEAD" };
                        let reply = fetch(method, &req.url, pq_only).await;
                        if let (Ok(cell), Some(addr)) = (
                            surb_reply_cell(&req.surb, reply.as_bytes(), &mut Csprng),
                            addr_of.get(&req.first),
                        ) {
                            let _ = sock.send_to(&frame_for_wire(&cell), *addr).await;
                        }
                    });
                }
            }
        }
        if stats_at.elapsed() >= Duration::from_secs(10) {
            stats_at = Instant::now();
            let s = node.lock().unwrap().stats.clone();
            let line = format!(
                "{{\"accepted\":{},\"forwarded\":{},\"delivered\":{},\"not_mine\":{},\"replays\":{},\"cover_evicted\":{},\"dropped_full\":{}}}",
                s.accepted,
                s.forwarded,
                s.delivered,
                s.not_mine,
                s.replays,
                s.cover_evicted,
                s.dropped_full
            );
            let _ = std::fs::write(dir.join("stats.json"), line);
        }
    }
}

/// A proxy request waiting for a real-or-drop slot: (method, url, reply channel).
type Queued = (String, String, oneshot::Sender<String>);

/// A request waiting for its reply, by the secrets of the reply block it carried.
struct Pending {
    reply_secret: [u8; 32],
    path_secrets: Vec<[u8; 32]>,
    done: oneshot::Sender<String>,
}

#[allow(clippy::too_many_arguments)]
async fn run_client(
    directory: &Path,
    provider: &str,
    pool_path: &Path,
    listen: SocketAddr,
    lambda_p: f64,
    lambda_l: f64,
    pull_ms: u64,
) -> Result<()> {
    let nodes = Arc::new(load_directory(directory)?);
    let provider_id = id16(provider)?;
    let prov = nodes
        .iter()
        .find(|n| n.keys.id == provider_id && n.role == "provider")
        .context("provider not in directory")?;
    let (prov_keys, prov_addr) = (prov.keys.clone(), prov.addr);
    let providers: Vec<MixKeys> = nodes
        .iter()
        .filter(|n| n.role == "provider")
        .map(|n| n.keys.clone())
        .collect();
    let addr_of: HashMap<[u8; 16], SocketAddr> =
        nodes.iter().map(|n| (n.keys.id, n.addr)).collect();
    let mut mailbox = [0u8; 16];
    Csprng.fill(&mut mailbox);
    let sock = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let queue: Arc<Mutex<VecDeque<Queued>>> = Arc::default();
    let pending: Arc<Mutex<Vec<Pending>>> = Arc::default();
    let loops: Arc<Mutex<VecDeque<[u8; 32]>>> = Arc::default();
    let used: Arc<Mutex<std::collections::HashSet<String>>> = Arc::default();

    // The HTTP proxy: "HEAD https://host/ HTTP/1.1" in, "HTTP/1.1 <status> ..." out.
    {
        let queue = queue.clone();
        let listener = TcpListener::bind(listen).await?;
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    continue;
                };
                let queue = queue.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let mut n = 0;
                    while n < buf.len() {
                        match tokio::time::timeout(Duration::from_secs(10), s.read(&mut buf[n..]))
                            .await
                        {
                            Ok(Ok(0)) | Err(_) | Ok(Err(_)) => break,
                            Ok(Ok(k)) => n += k,
                        }
                        if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let head = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let mut parts = head.split_whitespace();
                    let (Some(method), Some(url)) = (parts.next(), parts.next()) else {
                        return;
                    };
                    let (tx, rx) = oneshot::channel();
                    queue
                        .lock()
                        .unwrap()
                        .push_back((method.to_string(), url.to_string(), tx));
                    let reply = match tokio::time::timeout(Duration::from_secs(60), rx).await {
                        Ok(Ok(r)) => r,
                        _ => "HTTP/1.1 504 Gateway Timeout\r\n\r\n".into(),
                    };
                    let status = reply
                        .lines()
                        .next()
                        .unwrap_or("HTTP/1.1 502 Bad Gateway")
                        .to_string();
                    let _ = s
                        .write_all(
                            format!("{status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                                .as_bytes(),
                        )
                        .await;
                });
            }
        });
    }

    // Replies, loops and stray cells arrive on the socket after each pull.
    {
        let (sock, pending, loops) = (sock.clone(), pending.clone(), loops.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let Ok((n, _)) = sock.recv_from(&mut buf).await else {
                    continue;
                };
                let Some(cell) = unframe(&buf[..n]) else {
                    continue;
                };
                let mut p = pending.lock().unwrap();
                if let Some(i) = p.iter().position(|x| {
                    open_surb_reply(&x.reply_secret, &x.path_secrets, &cell).is_some()
                }) {
                    let x = p.remove(i);
                    let msg = open_surb_reply(&x.reply_secret, &x.path_secrets, &cell)
                        .unwrap_or_default();
                    let _ = x.done.send(String::from_utf8_lossy(&msg).into_owned());
                    continue;
                }
                drop(p);
                let mut l = loops.lock().unwrap();
                if let Some(i) = l.iter().position(|k| open_payload(&cell, k).is_some()) {
                    l.remove(i);
                }
            }
        });
    }

    // Pulls on a fixed schedule, whatever is waiting.
    {
        let sock = sock.clone();
        tokio::spawn(async move {
            let mut req = PULL_MAGIC.to_vec();
            req.extend_from_slice(&mailbox);
            let mut t = tokio::time::interval(Duration::from_millis(pull_ms));
            loop {
                t.tick().await;
                let _ = sock.send_to(&req, prov_addr).await;
            }
        });
    }

    // Loops (Poisson λL): around the network back to this mailbox.
    {
        let (sock, nodes, loops, addr_of, prov_keys) = (
            sock.clone(),
            nodes.clone(),
            loops.clone(),
            addr_of.clone(),
            prov_keys.clone(),
        );
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(exp_wait(lambda_l)).await;
                let path = random_path(&nodes, &prov_keys);
                let mut filler = [0u8; 32];
                Csprng.fill(&mut filler);
                if let Ok(c) = build_cell(&path, &mailbox, &filler, &mut Csprng) {
                    {
                        let mut l = loops.lock().unwrap();
                        l.push_back(c.payload_key);
                        while l.len() > 512 {
                            l.pop_front();
                        }
                    }
                    if let Some(a) = addr_of.get(&path[0].id) {
                        let _ = sock.send_to(&frame_for_wire(&c.cell), *a).await;
                    }
                }
            }
        });
    }

    // Real-or-drop (Poisson λP): a waiting request takes the slot, else a drop cell.
    loop {
        tokio::time::sleep(exp_wait(lambda_p)).await;
        let next = queue.lock().unwrap().pop_front();
        let built: Option<(Vec<u8>, [u8; 16])> = match next {
            Some((method, url, done)) => {
                let pool: Vec<PoolEntry> = std::fs::read(pool_path)
                    .ok()
                    .and_then(|b| serde_json::from_slice(&b).ok())
                    .unwrap_or_default();
                let fresh: Vec<&PoolEntry> = {
                    let u = used.lock().unwrap();
                    pool.iter().filter(|e| !u.contains(&e.surb[..64])).collect()
                };
                if fresh.is_empty() {
                    let _ = done.send("HTTP/1.1 503 Service Unavailable\r\n\r\n".into());
                    None
                } else {
                    let entry = fresh[rand::rng().random_range(0..fresh.len())].clone();
                    used.lock().unwrap().insert(entry.surb[..64].to_string());
                    let reply_path = random_path(&nodes, &prov_keys);
                    let my_surb = build_surb(&reply_path, &mailbox, &mut Csprng).ok();
                    match (my_surb, hex::decode(&entry.surb), id16(&entry.first)) {
                        (Some(my_surb), Ok(service_surb), Ok(first)) => {
                            let request = Request {
                                method,
                                url,
                                surb: my_surb.bytes.clone(),
                                first: reply_path[0].id,
                            };
                            let msg = request.encode();
                            match surb_reply_cell(&service_surb, &msg, &mut Csprng) {
                                Ok(cell) => {
                                    pending.lock().unwrap().push(Pending {
                                        reply_secret: my_surb.reply_secret,
                                        path_secrets: my_surb.path_secrets,
                                        done,
                                    });
                                    Some((cell, first))
                                }
                                Err(_) => {
                                    let _ = done.send("HTTP/1.1 502 Bad Gateway\r\n\r\n".into());
                                    None
                                }
                            }
                        }
                        _ => None,
                    }
                }
            }
            None => {
                // Drop cover: an indistinguishable cell to a random provider's drop box.
                let last = &providers[rand::rng().random_range(0..providers.len())];
                let path = random_path(&nodes, last);
                let mut filler = [0u8; 32];
                Csprng.fill(&mut filler);
                build_cell(&path, &DROP_MAILBOX, &filler, &mut Csprng)
                    .ok()
                    .map(|c| (c.cell, path[0].id))
            }
        };
        if let Some((cell, first)) = built
            && let Some(addr) = addr_of.get(&first)
        {
            let _ = sock.send_to(&frame_for_wire(&cell), *addr).await;
        }
    }
}

/// An Exp(rate) wait: the gap between Poisson events.
fn exp_wait(rate: f64) -> Duration {
    let u = loop {
        let u = Csprng.next_unit();
        if u > 0.0 {
            break u;
        }
    };
    Duration::from_secs_f64((-u.ln() / rate.max(1e-6)).min(3600.0))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let a = Args::parse();
    if !a.experimental {
        bail!("the option E daemon is experimental (lab only); pass --experimental");
    }
    match a.role {
        Role::Keygen { dir, addr, role } => keygen(&dir, addr, &role),
        Role::Mix {
            dir,
            directory,
            mean_delay_ms,
            service_pool,
            pool_size,
            allow_classical_tls13,
        } => {
            run_mix(
                &dir,
                &directory,
                mean_delay_ms,
                service_pool,
                pool_size,
                !allow_classical_tls13,
            )
            .await
        }
        Role::Client {
            directory,
            provider,
            pool,
            listen,
            lambda_p,
            lambda_l,
            pull_ms,
        } => {
            run_client(
                &directory, &provider, &pool, listen, lambda_p, lambda_l, pull_ms,
            )
            .await
        }
    }
}
