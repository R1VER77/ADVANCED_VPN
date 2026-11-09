use crate::config::{Identity, private_read};
use anyhow::{Context, Result, ensure};
use quinn::{
    ClientConfig, ServerConfig, TransportConfig,
    crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig},
};
use rustls::{
    RootCertStore,
    crypto::aws_lc_rs,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    os::fd::FromRawFd,
    os::unix::fs::FileExt,
    sync::{Arc, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use x509_parser::prelude::*;

/// Outer layer UDP payload of the legacy two-layer profile.
pub const OUTER_MTU: u16 = 1440;
/// Inner layer UDP payload of the legacy two-layer profile.
pub const INNER_MTU: u16 = 1350;
/// ALPN every layer must negotiate.
pub const ALPN: &[u8] = b"advanced-vpn/1";
/// Managed profiles nest one QUIC layer per server hop, built from the inside out:
/// the innermost layer uses QUIC's 1200-byte minimum UDP payload (RFC 9000) and
/// each outer layer adds 56 bytes (a short-header DATAGRAM packet costs ~32).
/// Three hops (1312/1256/1200) still fit the 1340-byte WireGuard carrier MTU.
/// The inner IP MTU is 1100 for every chain length.
pub const MAX_HOPS: usize = 3;
/// Inner IP MTU of managed profiles, for every chain length.
pub const MANAGED_IP_MTU: usize = 1100;
/// QUIC's minimum UDP payload (RFC 9000), used by the innermost layer.
pub const QUIC_MIN_PAYLOAD: u16 = 1200;
/// Extra payload budget each outer layer adds around the next one.
pub const LAYER_STEP: u16 = 56;
/// UDP payload of layer `index` (0 = first hop) in a chain of `layers` layers.
pub fn layer_payload(ip_mtu: usize, layers: usize, index: usize) -> u16 {
    if ip_mtu == 1280 {
        // Legacy v0.1 two-layer profile.
        return if index == 0 { OUTER_MTU } else { INNER_MTU };
    }
    QUIC_MIN_PAYLOAD + LAYER_STEP * (layers - 1 - index) as u16
}
/// The only accepted authentication algorithm: ML-DSA-65 (FIPS 204), for certificate
/// chains and for the TLS 1.3 CertificateVerify of both peers.
pub const SIGNATURE_SCHEME: rustls::SignatureScheme = rustls::SignatureScheme::ML_DSA_65;
/// The certificate signature algorithms webpki accepts: ML-DSA-65 only.
pub fn pq_signatures() -> rustls::crypto::WebPkiSupportedAlgorithms {
    static ALGORITHMS: OnceLock<rustls::crypto::WebPkiSupportedAlgorithms> = OnceLock::new();
    *ALGORITHMS.get_or_init(|| {
        let base = aws_lc_rs::default_provider().signature_verification_algorithms;
        let mapping: Vec<_> = base
            .mapping
            .iter()
            .copied()
            .filter(|(scheme, _)| *scheme == SIGNATURE_SCHEME)
            .collect();
        let all: Vec<_> = mapping
            .iter()
            .flat_map(|(_, algorithms)| algorithms.iter().copied())
            .collect();
        assert!(
            mapping.len() == 1 && !all.is_empty(),
            "ML-DSA-65 verification unavailable"
        );
        // Leaked once per process: rustls requires 'static algorithm tables.
        rustls::crypto::WebPkiSupportedAlgorithms {
            all: Box::leak(all.into_boxed_slice()),
            mapping: Box::leak(mapping.into_boxed_slice()),
        }
    })
}
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    let mut p = aws_lc_rs::default_provider();
    p.kx_groups = vec![aws_lc_rs::kx_group::X25519MLKEM768];
    p.cipher_suites = vec![aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384];
    p.signature_verification_algorithms = pq_signatures();
    Arc::new(p)
}
fn initial_suite() -> rustls::quic::Suite {
    // QUIC Initial protection is standardized AES-128 and is not application secrecy.
    let s = aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .unwrap();
    rustls::quic::Suite {
        suite: s,
        quic: s.quic.unwrap(),
    }
}
fn roots(i: &Identity) -> Result<RootCertStore> {
    let mut r = RootCertStore::empty();
    r.add(CertificateDer::from(private_read(&i.ca, 16384)?))?;
    Ok(r)
}
fn material(
    i: &Identity,
    fd: Option<i32>,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert = CertificateDer::from(private_read(&i.cert, 16384)?);
    certificate_lifetime(&cert)?;
    let key = if let Some(fd) = fd {
        // Duplicate the inherited descriptor; never take ownership of the caller's FD.
        // SAFETY: fcntl F_DUPFD_CLOEXEC duplicates an integer descriptor without pointers.
        let n = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        ensure!(n >= 0, "invalid inherited key descriptor");
        // SAFETY: n is a newly allocated owned descriptor from successful fcntl.
        let f = unsafe { File::from_raw_fd(n) };
        ensure!(f.metadata()?.len() <= 16384, "inherited key too large");
        // SAFETY: F_GET_SEALS reads flags on a valid descriptor without pointers.
        let seals = unsafe { libc::fcntl(n, libc::F_GET_SEALS) };
        let required =
            libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
        ensure!(
            seals >= 0 && seals & required == required,
            "key descriptor must be an immutable sealed memfd"
        );
        let mut b = vec![0; f.metadata()?.len() as usize];
        f.read_exact_at(&mut b, 0)?;
        b
    } else {
        private_read(&i.key, 16384)?
    };
    Ok((vec![cert], PrivatePkcs8KeyDer::from(key).into()))
}
/// QUIC transport settings: datagrams only (no streams), sized to `mtu`, with keep-alives.
///
/// Roaming between networks is handled below the QUIC layers: the inner layers ride on
/// the WireGuard carrier's stable overlay addresses, and the carrier (persistent
/// keepalive) re-learns the client's new address after a physical network change, so a
/// handover does not renegotiate the chain. The QUIC idle timeout stays short (10 s) so
/// a server frees a stale session quickly and the client can reconnect at once; keep-
/// alives every 2 s hold the path open through NAT. See `avpn help threat-model`.
pub fn transport(mtu: u16) -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    t.max_concurrent_bidi_streams(0u8.into())
        .max_concurrent_uni_streams(0u8.into())
        .datagram_receive_buffer_size(Some(65536))
        .datagram_send_buffer_size(65536)
        .receive_window(65536u32.into())
        .send_window(65536)
        .initial_mtu(mtu)
        .min_mtu(mtu)
        .mtu_discovery_config(None)
        .max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()))
        .keep_alive_interval(Some(Duration::from_secs(2)));
    Arc::new(t)
}
/// Server configuration for one layer: TLS 1.3 only, no 0-RTT or resumption, X25519MLKEM768,
/// and an ML-DSA-65 client certificate from this layer's authority required.
pub fn server(i: &Identity, fd: Option<i32>, mtu: u16) -> Result<ServerConfig> {
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots(i)?),
        provider(),
    )
    .build()?;
    let (cert, key) = material(i, fd)?;
    let mut t = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert, key)?;
    t.alpn_protocols = vec![ALPN.to_vec()];
    t.max_early_data_size = 0;
    t.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    let crypto = QuicServerConfig::with_initial(Arc::new(t), initial_suite())?;
    let mut s = ServerConfig::with_crypto(Arc::new(crypto));
    s.transport_config(transport(mtu))
        .max_incoming(4)
        .incoming_buffer_size(65536)
        .incoming_buffer_size_total(262144);
    Ok(s)
}
/// Client configuration for one layer: X25519MLKEM768 only, ML-DSA-65 on both sides, peer pinned.
pub fn client(i: &Identity, fd: Option<i32>, mtu: u16) -> Result<ClientConfig> {
    let (cert, key) = material(i, fd)?;
    let mut t = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots(i)?)
        .with_client_auth_cert(cert, key)?;
    t.alpn_protocols = vec![ALPN.to_vec()];
    t.enable_early_data = false;
    t.resumption = rustls::client::Resumption::disabled();
    let crypto = QuicClientConfig::with_initial(Arc::new(t), initial_suite())?;
    let mut c = ClientConfig::new(Arc::new(crypto));
    c.transport_config(transport(mtu));
    Ok(c)
}
/// Time left on a currently valid leaf certificate; refuses leaves valid for more than 24 hours.
pub fn certificate_lifetime(cert: &[u8]) -> Result<Duration> {
    let (_, parsed) =
        parse_x509_certificate(cert).map_err(|_| anyhow::anyhow!("invalid certificate"))?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    ensure!(
        parsed.validity().not_before.timestamp() <= now
            && parsed.validity().not_after.timestamp() > now,
        "certificate not currently valid"
    );
    ensure!(
        parsed.validity().not_after.timestamp() - parsed.validity().not_before.timestamp()
            <= 86400 + 600,
        "leaf validity exceeds 24h profile"
    );
    Ok(Duration::from_secs(
        (parsed.validity().not_after.timestamp() - now) as u64,
    ))
}
/// Verify a finished handshake (ALPN, hybrid-PQ group, pinned peer) and return how long the peer's leaf stays valid.
pub fn authenticated(c: &quinn::Connection, i: &Identity) -> Result<Duration> {
    let data = c
        .handshake_data()
        .context("missing handshake evidence")?
        .downcast::<HandshakeData>()
        .map_err(|_| anyhow::anyhow!("wrong handshake type"))?;
    ensure!(
        data.protocol.as_deref() == Some(ALPN)
            && data.negotiated_key_exchange_group == rustls::NamedGroup::X25519MLKEM768,
        "hybrid-PQ negotiation required"
    );
    let identity = c
        .peer_identity()
        .context("missing mTLS peer")?
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| anyhow::anyhow!("wrong peer identity type"))?;
    let cert = identity.first().context("missing leaf")?;
    let pinned_bytes = match i.pin_kind {
        crate::config::PinKind::Certificate => cert.as_ref(),
        crate::config::PinKind::Spki => {
            let (_, parsed) = parse_x509_certificate(cert)
                .map_err(|_| anyhow::anyhow!("invalid peer certificate"))?;
            parsed.tbs_certificate.subject_pki.raw
        }
    };
    let digest = format!("{:x}", Sha256::digest(pinned_bytes));
    ensure!(digest == i.peer_sha256, "peer revoked or not pinned");
    let peer = certificate_lifetime(cert)?;
    let own = certificate_lifetime(&private_read(&i.cert, 16384)?)?;
    Ok(peer.min(own))
}
