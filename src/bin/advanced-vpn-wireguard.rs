//! Original adapter to the unmodified MPL-2.0 GotaTun public API.
use advanced_vpn::config::private_read;
use anyhow::{Context, Result, ensure};
use clap::Parser;
use gotatun::device::{DeviceBuilder, Peer, daita::DaitaSettings};
use rand::SeedableRng;
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
fn secret(path: &Path, fd: Option<i32>) -> Result<Vec<u8>> {
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
            f.metadata()?.len() == 64,
            "expected private key plus preshared key"
        );
        let mut b = vec![0; 64];
        f.read_exact_at(&mut b, 0)?;
        Ok(b)
    } else {
        private_read(path, 64)
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
        c.endpoint
            .is_none_or(|a| a.is_ipv4() && a.port() != 0 && !a.ip().is_unspecified()),
        "bad endpoint"
    );
    let pubkey = decode32(&c.peer_public_hex)?;
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
    let b = zeroize::Zeroizing::new(secret(&c.identity.key, keyfd)?);
    ensure!(
        b.len() == 64 && b[32..].iter().any(|&x| x != 0),
        "nonzero PSK required"
    );
    // Bind the hardware envelope to a role-specific public descriptor.
    let _binding = private_read(&c.identity.cert, 4096)?;
    let mut peer = Peer::new(gotatun::x25519::PublicKey::from(pubkey))
        .with_allowed_ip(c.allowed_ip.parse()?)
        .with_preshared_key(b[32..].try_into()?);
    if let Some(endpoint) = c.endpoint {
        peer = peer.with_endpoint(endpoint);
    }
    peer.keepalive = Some(25);
    // Every hop builds the full strong machine set from its own OS-seeded RNG, so
    // each hop's defense schedule is independent (see advanced_vpn::daita).
    let mut rng = rand::rngs::StdRng::from_os_rng();
    let machines = advanced_vpn::daita::machines(&mut rng);
    let daita = DaitaSettings {
        maybenot_machines: machines,
        max_decoy_frac: 0.5,
        max_delay_frac: 0.5,
        max_delayed_packets: NonZeroUsize::new(128).unwrap(),
        min_delay_capacity: 32,
    };
    peer = peer.with_daita(daita);
    if a.check {
        println!(
            "{{\"configuration_valid\":true,\"wireguard\":\"GotaTun\",\"daita\":true,\"psk\":true}}"
        );
        return Ok(());
    }
    let public = peer.public_key;
    let mut device = DeviceBuilder::new()
        .with_default_udp()
        .udp_recv_buffer_size(65536)
        .udp_send_buffer_size(65536)
        .create_tun(&c.tun)?
        .with_private_key(gotatun::x25519::StaticSecret::from(<[u8; 32]>::try_from(
            &b[..32],
        )?))
        .with_listen_port(c.listen_port)
        .with_peer(peer)
        .build()
        .await?;
    if c.endpoint.is_some() {
        device.force_handshake(&public).await?;
    }
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            _=term.recv()=>break,
            _=tokio::signal::ctrl_c()=>break,
            _=device.wait()=>anyhow::bail!("carrier ended"),
            _=ticker.tick()=>{
                let peers=device.peers().await;let p=peers.first().context("peer disappeared")?;
                let d=p.stats.daita.as_ref().context("DAITA disabled")?;
                let stats=serde_json::json!({"schema":1,"daita":true,"handshake":p.stats.last_handshake.is_some(),
                    "rx_bytes":p.stats.rx_bytes,"tx_bytes":p.stats.tx_bytes,"tx_padding_bytes":d.tx_padding_bytes,
                    "rx_padding_bytes":d.rx_padding_bytes,"tx_decoy_bytes":d.tx_decoy_packet_bytes,"rx_decoy_bytes":d.rx_decoy_packet_bytes});
                let tmp=c.statistics.with_extension("tmp");std::fs::write(&tmp,serde_json::to_vec(&stats)?)?;std::fs::rename(tmp,&c.statistics)?;
                // A spent privacy budget stops the carrier; it never disables defenses.
                if let Some(budget)=c.byte_budget {ensure!((p.stats.rx_bytes.saturating_add(p.stats.tx_bytes) as u64) < budget,"traffic budget exhausted");}
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
