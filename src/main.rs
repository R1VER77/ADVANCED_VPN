use advanced_vpn::{config, run, tls};
#[cfg(test)]
mod crypto_tests;
use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version,
    about = "Experimental hybrid-PQ nested VPN; no implicit routing changes"
)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    check: bool,
    /// Inherited sealed memory descriptor, e.g. --key-fd inner=3. Never a secret value.
    #[arg(long)]
    key_fd: Vec<String>,
    /// Pre-opened TUN from an isolated application namespace.
    #[arg(long)]
    tun_fd: Option<i32>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // SAFETY: prctl and setrlimit are called with valid scalar/rlimit values. Disable core files and ptrace by ordinary same-UID processes.
    unsafe {
        libc::umask(0o077);
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &lim);
    }
    if let Err(_e) = entry().await {
        // Deliberately do not print provider errors, paths, certificates, addresses or keys.
        eprintln!("configuration or transport rejected; inspect documented policy checks");
        std::process::exit(1);
    }
}
async fn entry() -> Result<()> {
    let a = Args::parse();
    let c = config::Config::load(&a.config)?;
    let fds = config::key_fds(&a.key_fd)?;
    // Validate crypto and local key material even for --check; no TUN/socket is opened.
    if c.role == "client" {
        for (k, (lane, i)) in c.lanes().into_iter().enumerate() {
            let _ = tls::client(
                i,
                fds.get(lane).copied(),
                tls::layer_payload(c.mtu, c.layers, k),
            )?;
        }
    } else {
        let (lane, i, k) = c.server_layer()?;
        let _ = tls::client(
            i,
            fds.get(lane).copied(),
            tls::layer_payload(c.mtu, c.layers, k),
        )?;
    }
    if a.check {
        println!(
            "{{\"configuration_valid\":true,\"required_kx\":\"X25519MLKEM768\",\"required_cipher\":\"AES_256_GCM\"}}"
        );
        return Ok(());
    }
    let work = async {
        if c.role == "client" {
            run::client(&c, &fds, a.tun_fd).await
        } else {
            run::serve(&c, &fds, a.tun_fd).await
        }
    };
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {r=work=>r,_=tokio::signal::ctrl_c()=>Ok(()),_=term.recv()=>Ok(())}
}
