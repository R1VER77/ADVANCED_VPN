//! Camouflage for the WireGuard carrier: its datagrams ride as QUIC DATAGRAM frames
//! (RFC 9221) on UDP 443, so the link to the first hop looks like HTTP/3, not WireGuard.
//!
//! Outside in, the client's traffic is: QUIC (ALPN `h3`, the same hybrid X25519MLKEM768
//! key exchange browsers offer, an ECDSA server certificate pinned by its SPKI), then
//! WireGuard + DAITA, then the post-quantum QUIC layers of the chain. This layer adds no
//! secrecy the inner layers lack; it only changes what the link looks like.
//!
//! The server answers like a web server. A connection becomes a tunnel only after the
//! client proves the chain's cloak key on a reserved (GREASE) HTTP/3 stream type, bound
//! to that connection's TLS keys, so a recorded proof cannot be replayed. Anyone else
//! gets HTTP/3 SETTINGS and a `404` for every request, and nothing is forwarded.
use anyhow::{Context, Result, anyhow, ensure};
use bytes::Bytes;
use quinn::{
    ClientConfig, Connection, Endpoint, ServerConfig, TransportConfig, VarInt,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, aws_lc_rs},
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::net::UdpSocket;

/// ALPN offered and accepted: HTTP/3's.
pub const ALPN: &[u8] = b"h3";
/// UDP payload of every outer QUIC packet. A full WireGuard datagram ([`CARRIER_DATAGRAM`])
/// plus the QUIC short header, DATAGRAM framing and AEAD tag fits; the IP packet is 1448
/// bytes. Paths with a smaller MTU drop the packets: the tunnel fails closed.
pub const OUTER_MTU: u16 = 1420;
/// Largest WireGuard datagram the carrier sends: its 1340-byte MTU plus 32 bytes of framing.
pub const CARRIER_DATAGRAM: usize = 1372;
/// How long a new connection has to prove the cloak key before it is only a web client.
pub const AUTH_WINDOW: Duration = Duration::from_secs(3);
/// Length of the cloak key and of a proof.
pub const TOKEN_LEN: usize = 32;
/// The HTTP/3 unidirectional stream type that carries the proof: a reserved GREASE type
/// (0x1f * 3 + 0x21), which a real HTTP/3 server must ignore.
pub const TOKEN_STREAM: [u8; 2] = [0x40, 0x7e];
const EXPORTER_LABEL: &[u8] = b"EXPORTER-advanced-vpn-cloak";
/// While the client's session connects, WireGuard's datagrams wait (at most this many, for
/// at most [`HOLD_FOR`]) instead of being lost: the first handshake then gets through at
/// once, as it would on a direct path, and DAITA's shaping never starts before a session.
pub const HOLD: usize = 64;
/// How long a held datagram stays worth sending.
pub const HOLD_FOR: Duration = Duration::from_secs(2);
/// The server's HTTP/3 control stream: stream type 0x00, then SETTINGS with no dynamic
/// QPACK table and no blocked streams.
const H3_CONTROL: &[u8] = &[0x00, 0x04, 0x04, 0x01, 0x00, 0x07, 0x00];
/// The response to every request: a HEADERS frame with `:status: 404` and
/// `content-length: 0` (QPACK static table entries 27 and 4).
pub const H3_NOT_FOUND: &[u8] = &[0x01, 0x04, 0x00, 0x00, 0xdb, 0xc4];

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

fn equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The proof for this connection: HMAC of the cloak key over keying material exported
/// from the connection's TLS session (RFC 5705), so it is worthless on any other.
pub fn proof(c: &Connection, key: &[u8; TOKEN_LEN]) -> Result<[u8; TOKEN_LEN]> {
    let mut m = [0u8; 32];
    c.export_keying_material(&mut m, EXPORTER_LABEL, b"")
        .map_err(|_| anyhow!("keying material export failed"))?;
    Ok(hmac_sha256(key, &m))
}

fn provider() -> Arc<CryptoProvider> {
    // The default provider: TLS 1.3 suites and X25519MLKEM768 first, as browsers offer.
    Arc::new(aws_lc_rs::default_provider())
}

/// QUIC transport for the cloak: browser-like stream limits, DATAGRAM support sized for a
/// full WireGuard datagram, keep-alives through NAT, and one packet size for all data.
pub fn transport() -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    t.max_concurrent_bidi_streams(VarInt::from_u32(100))
        .max_concurrent_uni_streams(VarInt::from_u32(3))
        .datagram_receive_buffer_size(Some(1 << 20))
        .datagram_send_buffer_size(1 << 20)
        .initial_mtu(OUTER_MTU)
        .min_mtu(OUTER_MTU)
        .mtu_discovery_config(None)
        // Every packet carrying data is padded to OUTER_MTU, so QUIC's ACK frames and
        // packet-number lengths cannot vary the size an observer sees.
        .pad_to_mtu(true)
        .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()))
        .keep_alive_interval(Some(Duration::from_secs(5)));
    Arc::new(t)
}

/// Accepts exactly one server key: the one whose SubjectPublicKeyInfo hashes to the pin.
#[derive(Debug)]
struct Pinned {
    spki_sha256: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let (_, parsed) = x509_parser::parse_x509_certificate(end_entity).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        let digest: [u8; 32] = Sha256::digest(parsed.tbs_certificate.subject_pki.raw).into();
        if equal(&digest, &self.spki_sha256) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("QUIC uses TLS 1.3 only".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Client configuration: TLS 1.3, ALPN `h3`, the server key pinned, a server name (SNI)
/// only when the profile gives a cover name.
pub fn client_config(spki_sha256: [u8; 32], send_name: bool) -> Result<ClientConfig> {
    let p = provider();
    let mut t = rustls::ClientConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned {
            spki_sha256,
            provider: p,
        }))
        .with_no_client_auth();
    t.alpn_protocols = vec![ALPN.to_vec()];
    t.enable_sni = send_name;
    t.enable_early_data = false;
    t.resumption = rustls::client::Resumption::disabled();
    let mut c = ClientConfig::new(Arc::new(QuicClientConfig::try_from(t)?));
    c.transport_config(transport());
    Ok(c)
}

/// Server configuration: TLS 1.3, ALPN `h3`, the given ECDSA certificate (DER) and PKCS#8
/// key, no client certificate (a public web server asks for none).
pub fn server_config(cert: Vec<u8>, key: Vec<u8>) -> Result<ServerConfig> {
    let mut t = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert)],
            PrivatePkcs8KeyDer::from(key).into(),
        )?;
    t.alpn_protocols = vec![ALPN.to_vec()];
    t.max_early_data_size = 0;
    t.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    let mut s = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(t)?));
    s.transport_config(transport());
    Ok(s)
}

/// Counters for the status file. Counts only: never an address.
#[derive(Debug, Default)]
pub struct Stats {
    /// A proven session is up.
    pub connected: AtomicBool,
    /// Proven sessions so far.
    pub sessions: AtomicU64,
    /// Connections that never proved the key (web clients, probes).
    pub web_clients: AtomicU64,
    /// WireGuard datagrams sent to the peer.
    pub sent: AtomicU64,
    /// WireGuard datagrams received from the peer.
    pub received: AtomicU64,
    /// WireGuard datagrams dropped (no session, or the session refused them).
    pub dropped: AtomicU64,
}

impl Stats {
    /// The counters as the status file's JSON.
    pub fn json(&self, role: &str) -> serde_json::Value {
        let n = |a: &AtomicU64| a.load(Ordering::Relaxed);
        serde_json::json!({
            "schema": 1,
            "role": role,
            "connected": self.connected.load(Ordering::Relaxed),
            "sessions": n(&self.sessions),
            "web_clients": n(&self.web_clients),
            "sent": n(&self.sent),
            "received": n(&self.received),
            "dropped": n(&self.dropped),
        })
    }
}

fn add(a: &AtomicU64) {
    a.fetch_add(1, Ordering::Relaxed);
}

/// Answer as an HTTP/3 server: SETTINGS on a control stream, `404` to every request.
async fn web(c: Connection) {
    // The control stream stays open for the connection's life, as HTTP/3 requires.
    let _control = match c.open_uni().await {
        Ok(mut s) => s.write_all(H3_CONTROL).await.ok().map(|_| s),
        Err(_) => None,
    };
    while let Ok((mut send, mut recv)) = c.accept_bi().await {
        tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(2), recv.read_to_end(16384)).await;
            if send.write_all(H3_NOT_FOUND).await.is_ok() {
                let _ = send.finish();
            }
        });
    }
}

/// Read unidirectional streams until one carries a valid proof for this connection.
/// Other streams (a browser's control and QPACK streams) are drained and ignored.
async fn prove(c: &Connection, key: &[u8; TOKEN_LEN]) -> Result<()> {
    loop {
        let mut s = c.accept_uni().await?;
        let b = tokio::time::timeout(AUTH_WINDOW, s.read_to_end(64))
            .await
            .map_err(|_| anyhow!("slow stream"))?;
        if let Ok(b) = b
            && b.len() == TOKEN_STREAM.len() + TOKEN_LEN
            && b[..2] == TOKEN_STREAM
            && equal(&b[2..], &proof(c, key)?)
        {
            return Ok(());
        }
    }
}

/// Server: accept connections on `endpoint`; forward the proven session's datagrams to
/// WireGuard at `wireguard` and back. One session at a time; a newly proven connection
/// replaces the previous one (a reconnect or a roaming client).
pub async fn serve(
    endpoint: Endpoint,
    wireguard: SocketAddr,
    key: [u8; TOKEN_LEN],
    stats: Arc<Stats>,
) -> Result<()> {
    let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    udp.connect(wireguard).await?;
    let current: Arc<Mutex<Option<Connection>>> = Arc::default();
    {
        let (udp, current, stats) = (udp.clone(), current.clone(), stats.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok(n) = udp.recv(&mut buf).await else {
                    continue;
                };
                let session = current.lock().unwrap().clone();
                match session {
                    Some(c) if c.send_datagram(Bytes::copy_from_slice(&buf[..n])).is_ok() => {
                        add(&stats.sent)
                    }
                    _ => add(&stats.dropped),
                }
            }
        });
    }
    while let Some(incoming) = endpoint.accept().await {
        let (udp, current, stats) = (udp.clone(), current.clone(), stats.clone());
        tokio::spawn(async move {
            let Ok(c) = incoming.await else {
                return;
            };
            tokio::spawn(web(c.clone()));
            if !matches!(
                tokio::time::timeout(AUTH_WINDOW, prove(&c, &key)).await,
                Ok(Ok(()))
            ) {
                // Not ours: it stays an ordinary web client until it idles out.
                add(&stats.web_clients);
                return;
            }
            add(&stats.sessions);
            if let Some(old) = current.lock().unwrap().replace(c.clone()) {
                old.close(VarInt::from_u32(0x100), b"");
            }
            stats.connected.store(true, Ordering::Relaxed);
            while let Ok(d) = c.read_datagram().await {
                if udp.send(&d).await.is_ok() {
                    add(&stats.received);
                }
            }
            let mut cur = current.lock().unwrap();
            if cur.as_ref().is_some_and(|x| x.stable_id() == c.stable_id()) {
                *cur = None;
                stats.connected.store(false, Ordering::Relaxed);
            }
        });
    }
    Ok(())
}

/// Client: take WireGuard's datagrams on `local` (only from `wireguard`), carry them to
/// the server at `remote`, and hand the replies back to `wireguard`. Reconnects forever.
pub async fn connect(
    local: SocketAddr,
    wireguard: SocketAddr,
    remote: SocketAddr,
    cover_name: Option<String>,
    spki_sha256: [u8; 32],
    key: [u8; TOKEN_LEN],
    stats: Arc<Stats>,
) -> Result<()> {
    let udp = Arc::new(UdpSocket::bind(local).await?);
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config(spki_sha256, cover_name.is_some())?);
    // Without a cover name no SNI is sent; the name below is then only a placeholder.
    let name = cover_name.unwrap_or_else(|| "localhost".into());
    let current: Arc<Mutex<Option<Connection>>> = Arc::default();
    let held: Arc<Mutex<Held>> = Arc::default();
    {
        let (udp, current, held, stats) =
            (udp.clone(), current.clone(), held.clone(), stats.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, from)) = udp.recv_from(&mut buf).await else {
                    continue;
                };
                if from != wireguard {
                    continue;
                }
                let d = Bytes::copy_from_slice(&buf[..n]);
                let session = current.lock().unwrap().clone();
                match session {
                    Some(c) => match c.send_datagram(d) {
                        Ok(()) => add(&stats.sent),
                        Err(_) => add(&stats.dropped),
                    },
                    None => {
                        if held.lock().unwrap().push(d) {
                            add(&stats.dropped);
                        }
                    }
                }
            }
        });
    }
    loop {
        if let Ok(Ok(c)) =
            tokio::time::timeout(Duration::from_secs(10), endpoint.connect(remote, &name)?).await
            && let Err(e) = session(&c, &key, &udp, wireguard, &current, &held, &stats).await
        {
            c.close(VarInt::from_u32(0), b"");
            let _ = e;
        }
        *current.lock().unwrap() = None;
        stats.connected.store(false, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// WireGuard datagrams waiting for the client's session: bounded in count and age.
#[derive(Debug, Default)]
struct Held(std::collections::VecDeque<(std::time::Instant, Bytes)>);

impl Held {
    /// Keep `d`; returns true when an older datagram had to make room.
    fn push(&mut self, d: Bytes) -> bool {
        let full = self.0.len() >= HOLD;
        if full {
            self.0.pop_front();
        }
        self.0.push_back((std::time::Instant::now(), d));
        full
    }
    /// The datagrams still young enough to send, oldest first.
    fn take(&mut self) -> Vec<Bytes> {
        self.0
            .drain(..)
            .filter(|(at, _)| at.elapsed() < HOLD_FOR)
            .map(|(_, d)| d)
            .collect()
    }
}

async fn session(
    c: &Connection,
    key: &[u8; TOKEN_LEN],
    udp: &UdpSocket,
    wireguard: SocketAddr,
    current: &Mutex<Option<Connection>>,
    held: &Mutex<Held>,
    stats: &Stats,
) -> Result<()> {
    ensure!(
        c.max_datagram_size().unwrap_or(0) >= CARRIER_DATAGRAM,
        "path too small for a WireGuard datagram"
    );
    let mut s = c.open_uni().await?;
    let mut msg = TOKEN_STREAM.to_vec();
    msg.extend_from_slice(&proof(c, key)?);
    s.write_all(&msg).await?;
    s.finish()?;
    // The proof stream is reliable and ordered before nothing else: the server reads
    // datagrams only once it has the proof, and keeps early ones in its receive buffer.
    for d in held.lock().unwrap().take() {
        if c.send_datagram(d).is_ok() {
            add(&stats.sent);
        }
    }
    *current.lock().unwrap() = Some(c.clone());
    stats.connected.store(true, Ordering::Relaxed);
    add(&stats.sessions);
    loop {
        let d = c.read_datagram().await.context("session ended")?;
        if udp.send_to(&d, wireguard).await.is_ok() {
            add(&stats.received);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed test-only certificate for `cover.example` and its key.
    fn test_cert() -> (Vec<u8>, Vec<u8>, [u8; 32]) {
        let cert = hex::decode("3082013b3081e1a003020102020101300a06082a8648ce3d04030230183116301406035504030c0d636f7665722e6578616d706c65301e170d3236303130313030303030305a170d3335313233303030303030305a30183116301406035504030c0d636f7665722e6578616d706c653059301306072a8648ce3d020106082a8648ce3d03010703420004358535ee352a5e58c95668b81273a57c29c765d3308afcceb474db380eb710c78a5452f219e072b25906c13f45adc362a1d310dcb653b4815a297045418ecd1aa31c301a30180603551d110411300f820d636f7665722e6578616d706c65300a06082a8648ce3d0403020349003046022100faf8e78da7b89960cdc5de7199a9f595f06cfd912bdbc68f0b75965775d134bc022100e0653d374f0ae3b19782ec50c707f92f04a25c80d9bbbf966ad1ff305b4d3ee6").unwrap();
        let key = hex::decode("308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104208b5974120554727af44b7cde724f9bab5e02c50d4c689dd8c4f231f0ff67cf4aa14403420004358535ee352a5e58c95668b81273a57c29c765d3308afcceb474db380eb710c78a5452f219e072b25906c13f45adc362a1d310dcb653b4815a297045418ecd1a").unwrap();
        let pin: [u8; 32] =
            hex::decode("77b575ee6b1bc8e4c95eee0ff43e316cb797eca323b9d45642f1ad275fac1e71")
                .unwrap()
                .try_into()
                .unwrap();
        (cert, key, pin)
    }

    #[test]
    fn hmac_matches_rfc_4231() {
        assert_eq!(
            hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // Case 6: a key longer than the block is hashed first.
        assert_eq!(
            hex::encode(hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    /// A cloak server on loopback, with a stand-in WireGuard socket behind it.
    async fn server(key: [u8; 32]) -> (SocketAddr, UdpSocket, Arc<Stats>) {
        let (cert, k, _) = test_cert();
        let endpoint = Endpoint::server(
            server_config(cert, k).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stats = Arc::new(Stats::default());
        tokio::spawn(serve(
            endpoint,
            wg.local_addr().unwrap(),
            key,
            stats.clone(),
        ));
        (addr, wg, stats)
    }

    /// A raw client connection with the cloak's client configuration.
    async fn raw(addr: SocketAddr, pin: [u8; 32]) -> Result<(Endpoint, Connection)> {
        let mut e = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        e.set_default_client_config(client_config(pin, true)?);
        let c = tokio::time::timeout(Duration::from_secs(3), e.connect(addr, "cover.example")?)
            .await??;
        Ok((e, c))
    }

    async fn send_proof(c: &Connection, p: [u8; 32]) {
        let mut s = c.open_uni().await.unwrap();
        let mut msg = TOKEN_STREAM.to_vec();
        msg.extend_from_slice(&p);
        s.write_all(&msg).await.unwrap();
        s.finish().unwrap();
    }

    async fn nothing_arrives(wg: &UdpSocket) -> bool {
        let mut buf = [0u8; 2048];
        tokio::time::timeout(Duration::from_millis(500), wg.recv_from(&mut buf))
            .await
            .is_err()
    }

    #[tokio::test]
    async fn a_web_client_gets_404_and_reaches_nothing() {
        let (_, _, pin) = test_cert();
        let (addr, wg, stats) = server([7; 32]).await;
        let (_e, c) = raw(addr, pin).await.unwrap();
        assert_eq!(
            c.handshake_data()
                .unwrap()
                .downcast::<quinn::crypto::rustls::HandshakeData>()
                .unwrap()
                .protocol
                .as_deref(),
            Some(ALPN)
        );
        let (mut send, mut recv) = c.open_bi().await.unwrap();
        // HEADERS for `GET /` (the bytes do not matter to the server).
        send.write_all(&[0x01, 0x03, 0x00, 0x00, 0xd1])
            .await
            .unwrap();
        send.finish().unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(3), recv.read_to_end(1024))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, H3_NOT_FOUND);
        let _ = c.send_datagram(Bytes::from_static(b"not a session"));
        assert!(nothing_arrives(&wg).await);
        tokio::time::sleep(AUTH_WINDOW).await;
        assert_eq!(stats.web_clients.load(Ordering::Relaxed), 1);
        assert_eq!(stats.sessions.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn a_proven_session_carries_datagrams_both_ways() {
        let (_, _, pin) = test_cert();
        let key = [9; 32];
        let (addr, wg, stats) = server(key).await;
        // The real client: WireGuard stand-in <-> client cloak <-> server cloak <-> WireGuard.
        let local_wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local: SocketAddr = probe.local_addr().unwrap();
        drop(probe);
        let cs = Arc::new(Stats::default());
        tokio::spawn(connect(
            local,
            local_wg.local_addr().unwrap(),
            addr,
            Some("cover.example".into()),
            pin,
            key,
            cs.clone(),
        ));
        let mut buf = [0u8; 2048];
        let packet = vec![0x5a; CARRIER_DATAGRAM];
        let mut got = None;
        for _ in 0..50 {
            local_wg.send_to(&packet, local).await.unwrap();
            if let Ok(Ok((n, from))) =
                tokio::time::timeout(Duration::from_millis(100), wg.recv_from(&mut buf)).await
            {
                got = Some((n, from));
                break;
            }
        }
        let (n, from) = got.expect("a full-size WireGuard datagram reaches the server's WireGuard");
        assert_eq!(&buf[..n], &packet[..]);
        wg.send_to(b"reply", from).await.unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), local_wg.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"reply");
        assert!(stats.connected.load(Ordering::Relaxed) && cs.connected.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn a_proof_from_another_connection_or_key_is_refused() {
        let (_, _, pin) = test_cert();
        let key = [3; 32];
        let (addr, wg, stats) = server(key).await;
        // A proof made for one connection, replayed on another.
        let (_e1, first) = raw(addr, pin).await.unwrap();
        let replay = proof(&first, &key).unwrap();
        let (_e2, second) = raw(addr, pin).await.unwrap();
        send_proof(&second, replay).await;
        // And a proof under the wrong key.
        let (_e3, third) = raw(addr, pin).await.unwrap();
        send_proof(&third, proof(&third, &[4; 32]).unwrap()).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        for c in [&second, &third] {
            let _ = c.send_datagram(Bytes::from_static(b"let me in"));
        }
        assert!(nothing_arrives(&wg).await);
        assert_eq!(stats.sessions.load(Ordering::Relaxed), 0);
        // The right proof on its own connection works.
        send_proof(&first, replay).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(stats.sessions.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn the_client_refuses_a_server_key_it_has_not_pinned() {
        let (_, _, pin) = test_cert();
        let (addr, _wg, _) = server([1; 32]).await;
        let mut wrong = pin;
        wrong[0] ^= 1;
        assert!(raw(addr, wrong).await.is_err());
        assert!(raw(addr, pin).await.is_ok());
    }
}
