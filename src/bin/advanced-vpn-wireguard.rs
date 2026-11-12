//! Original adapter to the unmodified MPL-2.0 GotaTun public API.
use advanced_vpn::{config::private_read, daita::RateClass};
use anyhow::{Context, Result, ensure};
use clap::Parser;
use gotatun::device::{DeviceBuilder, Peer, daita::DaitaSettings};
use serde::Deserialize;
use std::{
    net::SocketAddr,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Key {
    key: PathBuf,
    cert: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
/// One admitted mesh member's carrier peer: its public key and its own overlay address.
/// The member's preshared key travels in the key material, in member order.
struct CarrierMember {
    public_hex: String,
    allowed_ip: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Carrier {
    schema: u32,
    role: String,
    tun: String,
    listen_port: u16,
    endpoint: Option<SocketAddr>,
    peer_public_hex: String,
    allowed_ip: String,
    identity: Key,
    defense: String,
    statistics: PathBuf,
    /// None: no carrier byte cap (the default). Some: fail-closed grant from the supervisor.
    byte_budget: Option<u64>,
    /// None: the shipped clock of `rate`. Some: the ephemeral defense database
    /// (tools/defense_db.py); the profile in force at startup sets the metered
    /// stream's clock, and "no profile in force" refuses the run.
    defense_db: Option<PathBuf>,
    /// The chain's signed rate class (advanced_vpn::daita::RateClass). Absent on
    /// bundles signed before rate classes: those run `metered`, the clock they had.
    rate: Option<String>,
    /// None: keepalive 25 s. Some("always-on"): keepalive 5 s — the self-sustaining
    /// cover machine starts within seconds of tunnel setup, so idle server links
    /// (relay<->relay) carry the same constant-rate stream as busy ones.
    cover: Option<String>,
    /// Mesh servers only: every admitted member. Empty/absent on the single-chain
    /// carrier, which keeps its one pinned peer.
    members: Option<Vec<CarrierMember>>,
}
#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    check: bool,
    #[arg(long)]
    key_fd: Vec<String>,
}
fn decode32(s: &str) -> Result<[u8; 32]> {
    let b = hex::decode(s)?;
    ensure!(b.len() == 32, "wrong public key length");
    Ok(b.try_into().unwrap())
}
fn secret(path: &Path, fd: Option<i32>, peers: usize) -> Result<Vec<u8>> {
    if let Some(fd) = fd {
        use std::{os::fd::FromRawFd, os::unix::fs::FileExt};
        // SAFETY: fcntl duplicates a descriptor; no pointer argument is used.
        let n = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        ensure!(n >= 0, "missing key FD");
        // SAFETY: n is a new owned descriptor.
        let f = unsafe { std::fs::File::from_raw_fd(n) };
        // SAFETY: reads seal flags from the owned descriptor.
        let seals = unsafe { libc::fcntl(n, libc::F_GET_SEALS) };
        ensure!(seals >= 0 && seals & 15 == 15, "immutable memfd required");
        ensure!(
            f.metadata()?.len() as usize == 32 + 32 * peers,
            "expected private key plus one preshared key per peer"
        );
        let mut b = vec![0; 32 + 32 * peers];
        f.read_exact_at(&mut b, 0)?;
        Ok(b)
    } else {
        private_read(path, (32 + 32 * peers) as u64)
    }
}
async fn work() -> Result<()> {
    let a = Args::parse();
    let c: Carrier = serde_json::from_slice(&private_read(&a.config, 16384)?)?;
    // Schema 2: the carrier is only reached through the cloak (advanced-vpn-cloak), so
    // WireGuard never appears on the wire. The client sends to its local cloak; the
    // first hop listens on 41194, which its firewall opens to loopback only.
    ensure!(
        c.schema == 2 && c.role == "wireguard",
        "wrong carrier schema"
    );
    ensure!(
        match c.endpoint {
            Some(e) => e == SocketAddr::from(([127, 0, 0, 1], 41196)) && c.listen_port == 41195,
            None => c.listen_port == 41194,
        },
        "the carrier must run behind the cloak"
    );
    ensure!(
        c.tun == "avwg0" && c.listen_port != 0,
        "fixed managed carrier required"
    );
    // There is one defense posture: strong, on every hop. A bundle signed with the
    // removed `balanced` profile is refused, so no chain ever runs half-defended;
    // re-enroll with a current bundle (`avpn init` signs strong only).
    ensure!(
        c.defense == "strong",
        "the balanced defense profile was removed: re-enroll with a current strong-only bundle"
    );
    ensure!(
        c.byte_budget
            .is_none_or(|b| (65536..=10_737_418_240).contains(&b)),
        "invalid per-run traffic budget"
    );
    ensure!(
        c.cover.as_deref().is_none_or(|v| v == "always-on"),
        "unknown cover mode"
    );
    let rate = match c.rate.as_deref() {
        None => RateClass::Metered,
        Some(name) => RateClass::parse(name).context("unknown rate class")?,
    };
    ensure!(
        c.defense_db.is_none() || rate == RateClass::Metered,
        "a defense database sets a metered clock; it cannot be combined with a faster rate class"
    );
    ensure!(
        c.endpoint
            .is_none_or(|a| a.is_ipv4() && a.port() != 0 && !a.ip().is_unspecified()),
        "bad endpoint"
    );
    let mesh = c.members.as_deref().unwrap_or(&[]);
    ensure!(
        mesh.len() <= 256 && (c.endpoint.is_none() || mesh.is_empty()),
        "members belong to a server carrier (no fixed endpoint), at most 256"
    );
    ensure!(
        mesh.is_empty() || (c.peer_public_hex.is_empty() && c.allowed_ip.is_empty()),
        "a mesh carrier names no single peer"
    );
    // Key material: this side's 32-byte private key, then one 32-byte preshared key per
    // admitted peer (one for the single chain, one per member in a mesh).
    let peers_expected = mesh.len().max(1);
    let keyfd = if a.key_fd.is_empty() {
        None
    } else {
        ensure!(a.key_fd.len() == 1, "one key FD required");
        Some(
            a.key_fd[0]
                .strip_prefix("wireguard=")
                .context("wrong key FD role")?
                .parse::<i32>()?,
        )
    };
    let b = zeroize::Zeroizing::new(secret(&c.identity.key, keyfd, peers_expected)?);
    ensure!(
        b.len() == 32 + 32 * peers_expected && b[32..].iter().any(|&x| x != 0),
        "nonzero PSK per peer required"
    );
    // Bind the hardware envelope to a role-specific public descriptor.
    let _binding = private_read(&c.identity.cert, 4096)?;
    let keepalive = Some(if c.cover.as_deref() == Some("always-on") {
        5
    } else {
        25
    });
    let mut peers = Vec::with_capacity(peers_expected);
    if mesh.is_empty() {
        let pubkey = decode32(&c.peer_public_hex)?;
        let mut peer = Peer::new(gotatun::x25519::PublicKey::from(pubkey))
            .with_allowed_ip(c.allowed_ip.parse()?)
            .with_preshared_key(b[32..64].try_into()?);
        if let Some(endpoint) = c.endpoint {
            peer = peer.with_endpoint(endpoint);
        }
        peer.keepalive = keepalive;
        peers.push(peer);
    } else {
        let mut seen = std::collections::BTreeSet::new();
        for (k, m) in mesh.iter().enumerate() {
            ensure!(
                m.public_hex.len() == 64
                    && m.public_hex.bytes().all(|b| b.is_ascii_hexdigit())
                    && seen.insert(m.allowed_ip.clone()),
                "member keys must be hex and member addresses unique"
            );
            let member_pub = decode32(&m.public_hex)?;
            let start = 32 + 32 * k;
            let mut peer = Peer::new(gotatun::x25519::PublicKey::from(member_pub))
                .with_allowed_ip(m.allowed_ip.parse()?)
                .with_preshared_key(b[start..start + 32].try_into()?);
            peer.keepalive = keepalive;
            peers.push(peer);
        }
    }
    // Every hop runs the constant-rate stream on the chain's signed clock (see
    // advanced_vpn::daita): traffic leaves only in fixed slots, idle or busy. With a
    // defense database the profile in force sets the (metered) clock instead.
    let loaded_profile = match &c.defense_db {
        Some(path) => {
            let db = advanced_vpn::daita::DefenseDb::load(path)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            Some(
                db.select(now)
                    .context("no defense profile in force; rotate the defense database")?
                    .clone(),
            )
        }
        None => None,
    };
    // The hold queue covers about 100 ms of slots (at least 128 packets). Strict: a
    // full queue drops (TCP sees a bottleneck), it never bursts outside the slots.
    let queue = ((rate.packets_per_second() / 10.0) as usize).clamp(128, 4096);
    let peers: Vec<Peer> = peers
        .into_iter()
        .map(|p| {
            // Every peer gets its own fresh DAITA machines: they are stateful.
            let machines = match &loaded_profile {
                Some(profile) => advanced_vpn::daita::machines_from_profile(profile),
                None => advanced_vpn::daita::machines(rate),
            };
            p.with_daita(DaitaSettings {
                maybenot_machines: machines,
                max_decoy_frac: 0.0,
                max_delay_frac: 0.0,
                max_delayed_packets: NonZeroUsize::new(queue).unwrap(),
                min_delay_capacity: 0,
                strict: true,
            })
        })
        .collect();
    if a.check {
        println!(
            "{{\"configuration_valid\":true,\"wireguard\":\"GotaTun\",\"daita\":true,\"psk\":true,\"rate\":\"{}\",\"defense_db\":{},\"cover_always_on\":{}}}",
            rate.name(),
            c.defense_db.is_some(),
            c.cover.as_deref() == Some("always-on"),
        );
        return Ok(());
    }
    let first_public = peers[0].public_key;
    let peer_count = peers.len();
    let mut device = DeviceBuilder::new()
        .with_default_udp()
        .udp_recv_buffer_size(65536)
        .udp_send_buffer_size(65536)
        .create_tun(&c.tun)?
        .with_private_key(gotatun::x25519::StaticSecret::from(<[u8; 32]>::try_from(
            &b[..32],
        )?))
        .with_listen_port(c.listen_port)
        .with_peers(peers)
        .build()
        .await?;
    if c.endpoint.is_some() {
        device.force_handshake(&first_public).await?;
    }
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            _=term.recv()=>break,
            _=tokio::signal::ctrl_c()=>break,
            _=device.wait()=>anyhow::bail!("carrier ended"),
            _=ticker.tick()=>{
                let peers=device.peers().await;
                anyhow::ensure!(peers.len()==peer_count,"peer disappeared");
                let mut rx_bytes=0usize;let mut tx_bytes=0usize;let mut tx_padding=0usize;let mut rx_padding=0usize;
                let mut tx_decoy=0usize;let mut rx_decoy=0usize;let mut handshake=false;
                for p in &peers {
                    let d=p.stats.daita.as_ref().context("DAITA disabled")?;
                    rx_bytes+=p.stats.rx_bytes;tx_bytes+=p.stats.tx_bytes;
                    tx_padding+=d.tx_padding_bytes;rx_padding+=d.rx_padding_bytes;
                    tx_decoy+=d.tx_decoy_packet_bytes;rx_decoy+=d.rx_decoy_packet_bytes;
                    handshake|=p.stats.last_handshake.is_some();
                }
                let stats=serde_json::json!({"schema":1,"daita":true,"handshake":handshake,
                    "peers":peers.len(),"rx_bytes":rx_bytes,"tx_bytes":tx_bytes,"tx_padding_bytes":tx_padding,
                    "rx_padding_bytes":rx_padding,"tx_decoy_bytes":tx_decoy,"rx_decoy_bytes":rx_decoy});
                let tmp=c.statistics.with_extension("tmp");std::fs::write(&tmp,serde_json::to_vec(&stats)?)?;std::fs::rename(tmp,&c.statistics)?;
                // A spent privacy budget stops the carrier; it never disables defenses.
                if let Some(budget)=c.byte_budget {ensure!((rx_bytes.saturating_add(tx_bytes) as u64) < budget,"traffic budget exhausted");}
            }
        }
    }
    device.stop().await;
    Ok(())
}
#[tokio::main(flavor = "current_thread")]
async fn main() {
    // SAFETY: scalar process hardening and a valid rlimit pointer.
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
        eprintln!("carrier policy or transport refused");
        std::process::exit(1);
    }
}
