//! Bounded owned-exit DNS-over-TLS forwarder. No DNS query logging or persistent cache.
use advanced_vpn::config::private_read;
use anyhow::{Result, ensure};
use clap::Parser;
use rustls::pki_types::{CertificateDer, ServerName};
use serde::Deserialize;
use std::{
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
    upstream: SocketAddr,
    server_name: String,
    test_ca: Option<PathBuf>,
}
#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    check: bool,
}
struct Resolver {
    tls: TlsConnector,
    addr: SocketAddr,
    name: ServerName<'static>,
    slots: Arc<Semaphore>,
    count: AtomicU64,
}
impl Resolver {
    async fn query(&self, b: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            b.len() >= 12 && b.len() <= 4096 && b[2] & 0x80 == 0,
            "bad DNS request"
        );
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
        count: AtomicU64::new(0),
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
                if peer.ip()!=c.client_ip || n>4096 || !budget.admit(n){continue;}
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
                if peer.ip()!=c.client_ip || !budget.admit(4096){continue;}
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
