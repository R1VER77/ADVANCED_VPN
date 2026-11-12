//! The camouflage process: carries the WireGuard carrier's datagrams as QUIC that looks
//! like HTTP/3 on UDP 443 (see `advanced_vpn::cloak`). Runs on the client and on the
//! chain's first hop, without capabilities; keys arrive only as sealed memfds.
use advanced_vpn::{
    cloak,
    config::{private_read, sealed_fd},
};
use anyhow::{Context, Result, ensure};
use clap::Parser;
use serde::Deserialize;
use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema: u32,
    role: String,
    listen: SocketAddr,
    wireguard: SocketAddr,
    remote: Option<SocketAddr>,
    cover_name: Option<String>,
    server_spki_sha256: Option<String>,
    cert: Option<PathBuf>,
    statistics: PathBuf,
}
#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    check: bool,
    /// `token=N` (both roles) and `cloak=N` (server: the ECDSA key, PKCS#8).
    #[arg(long)]
    key_fd: Vec<String>,
}

fn fds(items: &[String]) -> Result<BTreeMap<String, i32>> {
    let mut out = BTreeMap::new();
    for s in items {
        let (role, fd) = s
            .split_once('=')
            .context("key-fd must be token=N or cloak=N")?;
        ensure!(matches!(role, "token" | "cloak"), "unknown key role");
        let fd: i32 = fd.parse()?;
        ensure!(
            fd >= 3 && out.insert(role.to_string(), fd).is_none(),
            "duplicate or invalid key descriptor"
        );
    }
    Ok(out)
}

fn validate(c: &Config) -> Result<()> {
    ensure!(c.schema == 1, "wrong cloak schema");
    let local = |a: &SocketAddr, port: u16| a.ip().is_loopback() && a.is_ipv4() && a.port() == port;
    if let Some(name) = &c.cover_name {
        ensure!(
            !name.is_empty()
                && name.len() <= 253
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'),
            "bad cover name"
        );
    }
    match c.role.as_str() {
        "client" => {
            ensure!(
                local(&c.listen, 41196) && local(&c.wireguard, 41195),
                "fixed client cloak addresses required"
            );
            let r = c.remote.context("client needs the server address")?;
            ensure!(
                r.is_ipv4() && !r.ip().is_unspecified() && r.port() != 0,
                "bad server address"
            );
            ensure!(c.cert.is_none(), "a client has no certificate");
            let pin = c
                .server_spki_sha256
                .as_deref()
                .context("client needs the server pin")?;
            ensure!(
                pin.len() == 64 && pin.bytes().all(|b| b.is_ascii_hexdigit()),
                "bad server pin"
            );
        }
        "server" => {
            ensure!(
                c.listen == "0.0.0.0:8443".parse()? && local(&c.wireguard, 41194),
                "fixed server cloak addresses required"
            );
            ensure!(
                c.remote.is_none() && c.server_spki_sha256.is_none(),
                "a server pins no peer"
            );
            ensure!(c.cert.is_some(), "server needs its certificate");
        }
        _ => anyhow::bail!("unknown cloak role"),
    }
    Ok(())
}

async fn work() -> Result<()> {
    let a = Args::parse();
    let c: Config = serde_json::from_slice(&private_read(&a.config, 16384)?)?;
    validate(&c)?;
    let fds = fds(&a.key_fd)?;
    // The token descriptor holds one 32-byte proof key per admitted member (exactly
    // one on a client and on a single-chain server, up to 256 on a mesh server).
    let raw = sealed_fd(*fds.get("token").context("token key required")?, 32 * 256)?;
    ensure!(
        !raw.is_empty() && raw.len() % cloak::TOKEN_LEN == 0,
        "token keys are 32 bytes each"
    );
    let tokens: Vec<[u8; cloak::TOKEN_LEN]> = raw
        .chunks_exact(cloak::TOKEN_LEN)
        .map(|t| t.try_into().expect("chunk length"))
        .collect();
    let stats = Arc::new(cloak::Stats::default());
    let task = if c.role == "server" {
        let cert = private_read(c.cert.as_ref().unwrap(), 16384)?;
        let key = sealed_fd(*fds.get("cloak").context("server key required")?, 4096)?;
        let config = cloak::server_config(cert.clone(), key.clone())?;
        let tls_config = cloak::tls_server_config(cert, key)?;
        if a.check {
            println!("{{\"configuration_valid\":true,\"role\":\"server\"}}");
            return Ok(());
        }
        let endpoint = quinn::Endpoint::server(config, c.listen)?;
        let tcp_listener = tokio::net::TcpListener::bind(c.listen).await?;
        let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
        let (wg, tokens_tcp, stats_quic, stats_tcp) =
            (c.wireguard, tokens.clone(), stats.clone(), stats.clone());
        tokio::spawn(async move {
            tokio::select! {
                r = cloak::serve(endpoint, c.wireguard, tokens, stats_quic) => r,
                r = cloak::serve_tcp(tcp_listener, acceptor, wg, tokens_tcp, stats_tcp) => r,
            }
        })
    } else {
        ensure!(!fds.contains_key("cloak"), "a client has no server key");
        ensure!(tokens.len() == 1, "a client proves exactly one cloak key");
        let token = tokens[0];
        let pin: [u8; 32] = hex::decode(c.server_spki_sha256.as_deref().unwrap())?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad pin"))?;
        cloak::client_config(pin, c.cover_name.is_some())?;
        if a.check {
            println!("{{\"configuration_valid\":true,\"role\":\"client\"}}");
            return Ok(());
        }
        tokio::spawn(cloak::connect(
            c.listen,
            c.wireguard,
            c.remote.unwrap(),
            c.cover_name.clone(),
            pin,
            token,
            stats.clone(),
        ))
    };
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            _ = term.recv() => break,
            _ = tokio::signal::ctrl_c() => break,
            _ = ticker.tick() => {
                anyhow::ensure!(!task.is_finished(), "cloak stopped");
                let tmp = c.statistics.with_extension("tmp");
                std::fs::write(&tmp, serde_json::to_vec(&stats.json(&c.role))?)?;
                std::fs::rename(tmp, &c.statistics)?;
            }
        }
    }
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
    if let Err(e) = work().await {
        // The reason, never an address or key.
        eprintln!("cloak refused: {}", e.root_cause());
        std::process::exit(1);
    }
}
