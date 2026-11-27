//! Camouflage for the WireGuard carrier: its datagrams ride as QUIC DATAGRAM frames
//! (RFC 9221) on UDP 443, with automatic fallback to TLS 1.3 over TCP 443 when a network
//! blocks UDP, so the link to the first hop looks like HTTP/3 or HTTPS, not WireGuard.
//!
//! Outside in, the client's traffic is: QUIC (ALPN `h3`, or TLS 1.3 `http/1.1` on TCP 443
//! when UDP is blocked, with the same hybrid X25519MLKEM768 key exchange browsers offer and
//! an ECDSA server certificate pinned by its SPKI), then WireGuard + DAITA, then the
//! post-quantum QUIC layers of the chain. This layer adds no secrecy the inner layers lack;
//! it only changes what the link looks like.
//!
//! The server answers like a web origin. A connection becomes a tunnel only after the
//! client proves the chain's cloak key bound to that connection's TLS exporter (RFC 5705),
//! so a recorded proof cannot be replayed. Anyone else gets a realistic static HTML page
//! (`200 OK`) on both HTTP/3 and HTTPS, and nothing is forwarded.
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
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// ALPN offered and accepted on UDP 443: HTTP/3's.
pub const ALPN: &[u8] = b"h3";
/// ALPN offered and accepted on the TCP 443 fallback: HTTP/1.1's.
pub const ALPN_TCP: &[u8] = b"http/1.1";
/// UDP payload of every outer QUIC packet (and fixed cell size on the TCP/TLS fallback).
/// A full WireGuard datagram ([`CARRIER_DATAGRAM`]) plus the QUIC short header, DATAGRAM
/// framing and AEAD tag fits; the IP packet is 1448 bytes. Paths with a smaller MTU drop
/// the packets: the tunnel fails closed.
pub const OUTER_MTU: u16 = 1420;
/// Fixed cell size on the TCP/TLS 1.3 fallback carrier: 2-byte big-endian length followed
/// by the WireGuard datagram and zero padding to [`OUTER_MTU`].
pub const TCP_CELL_LEN: usize = OUTER_MTU as usize;
/// Largest WireGuard datagram the carrier sends: its 1340-byte MTU plus 32 bytes of framing.
pub const CARRIER_DATAGRAM: usize = 1372;
/// How long a new connection has to prove the cloak key before it is only a web client.
pub const AUTH_WINDOW: Duration = Duration::from_secs(3);
/// Behind an I2P front (`cypherpunk_vpn` tools/i2p.py) a stream crosses I2P tunnels: its
/// TLS handshake and proof get this long instead of [`AUTH_WINDOW`]. Only connections
/// from loopback (the local I2P router) get it on the server.
pub const FRONT_WINDOW: Duration = Duration::from_secs(30);
/// How long the client waits for QUIC/h3 before falling back to TCP/TLS 1.3.
pub const QUIC_FALLBACK_TIMEOUT: Duration = Duration::from_secs(2);
/// How often a client on the TCP/TLS fallback probes QUIC/h3 in the background to upgrade.
pub const QUIC_PROBE_INTERVAL: Duration = Duration::from_secs(10);
/// Length of the cloak key and of a proof.
pub const TOKEN_LEN: usize = 32;
/// The HTTP/3 unidirectional stream type that carries the proof: a reserved GREASE type
/// (0x1f * 4 + 0x21), which a real HTTP/3 server must ignore.
pub const TOKEN_STREAM: [u8; 2] = [0x40, 0x9d];
/// V2 server confirmation on a separate GREASE unidirectional stream.
pub const SERVER_CONFIRM_STREAM: [u8; 2] = [0x40, 0xbc];
const EXPORTER_LABEL: &[u8] = b"EXPORTER-cypherpunk-vpn-cloak-v2";
/// While the client's session connects, WireGuard's datagrams wait (at most this many, for
/// at most [`HOLD_FOR`]) instead of being lost: the first handshake then gets through at
/// once, as it would on a direct path, and DAITA's shaping never starts before a session.
pub const HOLD: usize = 64;
/// How long a held datagram stays worth sending.
pub const HOLD_FOR: Duration = Duration::from_secs(2);
/// The server's HTTP/3 control stream: stream type 0x00, then SETTINGS with no dynamic
/// QPACK table and no blocked streams.
const H3_CONTROL: &[u8] = &[0x00, 0x04, 0x04, 0x01, 0x00, 0x07, 0x00];
/// HTTP/3 HEADERS frame with `:status: 200` (QPACK static table 25, `0xd9`) and
/// `content-type: text/html; charset=utf-8` (QPACK static table 52, `0xf4`).
pub const H3_DECOY_HEADERS: &[u8] = &[0x01, 0x04, 0x00, 0x00, 0xd9, 0xf4];
/// Legacy alias kept for callers that check the HTTP/3 web response prefix.
pub const H3_NOT_FOUND: &[u8] = H3_DECOY_HEADERS;
/// Static decoy HTML page served to unauthenticated HTTP/3 and HTTPS probes.
pub const DECOY_HTML: &[u8] = b"<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n<title>Edge Node</title>\n<style>body{font-family:system-ui,sans-serif;max-width:42rem;margin:4rem auto;padding:0 1rem;color:#222;line-height:1.5}h1{font-size:1.3rem}</style>\n</head>\n<body>\n<main>\n<h1>Edge Static Origin</h1>\n<p>This node serves static assets for configured origins.</p>\n</main>\n</body>\n</html>\n";

/// Complete HTTP/3 decoy response: `:status: 200` HEADERS frame followed by a DATA frame
/// carrying [`DECOY_HTML`].
pub fn h3_decoy_response() -> Vec<u8> {
    let n = DECOY_HTML.len();
    debug_assert!((64..16384).contains(&n));
    let mut out = Vec::with_capacity(H3_DECOY_HEADERS.len() + 3 + n);
    out.extend_from_slice(H3_DECOY_HEADERS);
    // HTTP/3 DATA frame (type 0x00) with 2-byte QUIC varint length (0x4000 | len).
    out.push(0x00);
    out.extend_from_slice(&((0x4000u16 | n as u16).to_be_bytes()));
    out.extend_from_slice(DECOY_HTML);
    out
}

/// Complete HTTP/1.1 decoy response served on TCP/TLS when no proof is presented.
pub fn http1_decoy_response() -> Vec<u8> {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nCache-Control: public, max-age=300\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        DECOY_HTML.len()
    );
    let mut out = header.into_bytes();
    out.extend_from_slice(DECOY_HTML);
    out
}

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

/// The proof for a QUIC connection: HMAC of the cloak key over keying material exported
/// from the connection's TLS session (RFC 5705), so it is worthless on any other.
pub fn proof(c: &Connection, key: &[u8; TOKEN_LEN]) -> Result<[u8; TOKEN_LEN]> {
    let mut m = [0u8; 32];
    c.export_keying_material(&mut m, EXPORTER_LABEL, b"")
        .map_err(|_| anyhow!("keying material export failed"))?;
    Ok(role_proof(key, &m, b"client"))
}

/// The same exporter proof for a `rustls` TCP/TLS 1.3 connection.
pub fn tls_proof<D>(
    c: &rustls::ConnectionCommon<D>,
    key: &[u8; TOKEN_LEN],
) -> Result<[u8; TOKEN_LEN]> {
    let mut m = [0u8; 32];
    c.export_keying_material(&mut m, EXPORTER_LABEL, Some(b""))
        .map_err(|_| anyhow!("TLS keying material export failed"))?;
    Ok(role_proof(key, &m, b"client"))
}

fn role_proof(key: &[u8; TOKEN_LEN], exporter: &[u8; 32], role: &[u8]) -> [u8; TOKEN_LEN] {
    let mut message = b"cypherpunk-vpn/cloak/v2/".to_vec();
    message.extend_from_slice(role);
    message.push(0);
    message.extend_from_slice(exporter);
    hmac_sha256(key, &message)
}

fn server_proof(c: &Connection, key: &[u8; TOKEN_LEN]) -> Result<[u8; TOKEN_LEN]> {
    let mut m = [0u8; 32];
    c.export_keying_material(&mut m, EXPORTER_LABEL, b"")
        .map_err(|_| anyhow!("keying material export failed"))?;
    Ok(role_proof(key, &m, b"server"))
}

fn tls_server_proof<D>(
    c: &rustls::ConnectionCommon<D>,
    key: &[u8; TOKEN_LEN],
) -> Result<[u8; TOKEN_LEN]> {
    let mut m = [0u8; 32];
    c.export_keying_material(&mut m, EXPORTER_LABEL, Some(b""))
        .map_err(|_| anyhow!("keying material export failed"))?;
    Ok(role_proof(key, &m, b"server"))
}

async fn send_confirmation(c: &Connection, key: &[u8; TOKEN_LEN]) -> Result<()> {
    let mut stream = c.open_uni().await?;
    let mut message = SERVER_CONFIRM_STREAM.to_vec();
    message.extend_from_slice(&server_proof(c, key)?);
    stream.write_all(&message).await?;
    stream.finish()?;
    Ok(())
}

async fn confirm_server(c: &Connection, key: &[u8; TOKEN_LEN]) -> Result<()> {
    for _ in 0..16 {
        let mut stream = c.accept_uni().await?;
        let mut first = [0u8; 1];
        stream.read_exact(&mut first).await?;
        let mut typed = false;
        if first[0] == SERVER_CONFIRM_STREAM[0] {
            let mut second = [0u8; 1];
            stream.read_exact(&mut second).await?;
            typed = second[0] == SERVER_CONFIRM_STREAM[1];
        }
        if !typed {
            // HTTP/3 control/QPACK streams may remain open: never wait for their EOF
            // on the authentication path. Drains are byte-, time- and count-bounded.
            tokio::spawn(async move {
                let _ = tokio::time::timeout(AUTH_WINDOW, stream.read_to_end(4096)).await;
            });
            continue;
        }
        let body = stream.read_to_end(TOKEN_LEN).await?;
        ensure!(
            equal(&body, &server_proof(c, key)?),
            "server key confirmation failed"
        );
        return Ok(());
    }
    Err(anyhow!("too many streams before server confirmation"))
}

fn response_confirmation(header: &[u8]) -> Option<[u8; TOKEN_LEN]> {
    let text = std::str::from_utf8(header).ok()?;
    let mut result = None;
    for line in text.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("etag")
        {
            if result.is_some() {
                return None;
            }
            let value = value.trim();
            if value.len() != 66 || !value.starts_with('"') || !value.ends_with('"') {
                return None;
            }
            result = hex::decode(&value[1..65]).ok()?.try_into().ok();
            result?;
        }
    }
    result
}

fn provider() -> Arc<CryptoProvider> {
    // The default provider: TLS 1.3 suites and X25519MLKEM768 first, as browsers offer, so
    // the handshake looks like any browser's. Classical groups stay offered for that look
    // only: no tunnel ever runs over them (see `quic_hybrid` / `tls_hybrid`).
    Arc::new(aws_lc_rs::default_provider())
}

/// Whether a QUIC connection's TLS key exchange was hybrid post-quantum (X25519MLKEM768).
/// A cloak tunnel exists only over such a connection: the server answers a correct proof on
/// any other with the decoy, and the client never sends its proof over one.
pub fn quic_hybrid(c: &Connection) -> bool {
    c.handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .is_some_and(|d| d.negotiated_key_exchange_group == rustls::NamedGroup::X25519MLKEM768)
}

/// The same check for a `rustls` TCP/TLS 1.3 connection.
pub fn tls_hybrid<D>(c: &rustls::ConnectionCommon<D>) -> bool {
    c.negotiated_key_exchange_group()
        .is_some_and(|g| g.name() == rustls::NamedGroup::X25519MLKEM768)
}

/// QUIC transport for the cloak: browser-like stream limits, DATAGRAM support sized for a
/// full WireGuard datagram, a 4 MiB initial window so high-rate streams (`fast` / `line`)
/// do not self-drop during slow-start, keep-alives through NAT, and one packet size for all data.
pub fn transport() -> Arc<TransportConfig> {
    // BBR, not loss-based NewReno: on real-systemd KVM guests a few early losses
    // collapsed NewReno's window to ~3 packets and datagram sends stalled (about one
    // per second), which the client's carrier watch then turned into a restart loop.
    // Measured 2026-11-14, 3 runs x 3 fetches: NewReno 4/9 fetches, BBR 9/9.
    let mut cc = quinn::congestion::BbrConfig::default();
    cc.initial_window(4 << 20);
    transport_with(Arc::new(cc))
}

/// The transport of both ends while the wire clock runs: the same, but with a fixed window
/// (the server's side: [`server_config_clocked`]).
/// The stream's rate is set by the clock and agreed in advance, so congestion control has
/// nothing to decide; BBR held datagrams back by up to 0.3 s when its estimate dipped
/// below the stream's rate, and a packet that reaches the socket after its slot goes out
/// at once, on quinn's timing instead of the grid (docs/evidence/KERNEL_PACING.json,
/// counters). A window above `u32::MAX` also turns quinn's own pacing off.
fn clocked_transport() -> Arc<TransportConfig> {
    // On a clocked stream, full-size datagrams leave at 50-16,000 pps in both directions
    // and piggyback QUIC ACKs automatically. Raising the standalone ACK threshold suppresses
    // unpadded ACK-only upstream bursts (WF leak vector), while shortening max_ack_delay to
    // 25 ms speeds up loss recovery without hurting wire flatness.
    transport_with_ack(Arc::new(FixedWindow), 256, Duration::from_millis(25))
}

/// A congestion "controller" that never limits: the wire clock does.
#[derive(Clone, Debug)]
struct FixedWindow;

const FIXED_WINDOW: u64 = 1 << 40;

impl quinn::congestion::Controller for FixedWindow {
    fn on_congestion_event(
        &mut self,
        _: std::time::Instant,
        _: std::time::Instant,
        _: bool,
        _: u64,
    ) {
    }
    fn on_mtu_update(&mut self, _: u16) {}
    fn window(&self) -> u64 {
        FIXED_WINDOW
    }
    fn clone_box(&self) -> Box<dyn quinn::congestion::Controller> {
        Box::new(self.clone())
    }
    fn initial_window(&self) -> u64 {
        FIXED_WINDOW
    }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

impl quinn::congestion::ControllerFactory for FixedWindow {
    fn build(
        self: Arc<Self>,
        _: std::time::Instant,
        _: u16,
    ) -> Box<dyn quinn::congestion::Controller> {
        Box::new(FixedWindow)
    }
}

fn transport_with(
    cc: Arc<dyn quinn::congestion::ControllerFactory + Send + Sync>,
) -> Arc<TransportConfig> {
    transport_with_ack(cc, 64, Duration::from_millis(100))
}

fn transport_with_ack(
    cc: Arc<dyn quinn::congestion::ControllerFactory + Send + Sync>,
    ack_threshold: u32,
    max_ack_delay: Duration,
) -> Arc<TransportConfig> {
    let mut ack = quinn::AckFrequencyConfig::default();
    ack.ack_eliciting_threshold(VarInt::from_u32(ack_threshold))
        .max_ack_delay(Some(max_ack_delay));
    let mut t = TransportConfig::default();
    t.max_concurrent_bidi_streams(VarInt::from_u32(100))
        .max_concurrent_uni_streams(VarInt::from_u32(4))
        .datagram_receive_buffer_size(Some(4 << 20))
        .datagram_send_buffer_size(4 << 20)
        .receive_window(VarInt::from_u32(4 << 20))
        .send_window(4 << 20)
        .congestion_controller_factory(cc)
        .ack_frequency_config(Some(ack))
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
        Err(rustls::Error::General("the cloak uses TLS 1.3 only".into()))
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

fn rustls_client(
    spki_sha256: [u8; 32],
    send_name: bool,
    alpn: &[u8],
) -> Result<rustls::ClientConfig> {
    let p = provider();
    let mut t = rustls::ClientConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned {
            spki_sha256,
            provider: p,
        }))
        .with_no_client_auth();
    t.alpn_protocols = vec![alpn.to_vec()];
    t.enable_sni = send_name;
    t.enable_early_data = false;
    t.resumption = rustls::client::Resumption::disabled();
    Ok(t)
}

fn rustls_server(cert: Vec<u8>, key: Vec<u8>, alpn: &[u8]) -> Result<rustls::ServerConfig> {
    let mut t = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert)],
            PrivatePkcs8KeyDer::from(key).into(),
        )?;
    t.alpn_protocols = vec![alpn.to_vec()];
    t.max_early_data_size = 0;
    t.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Ok(t)
}

/// Client QUIC configuration: TLS 1.3, ALPN `h3`, the server key pinned, a server name (SNI)
/// only when the profile gives a cover name.
pub fn client_config(spki_sha256: [u8; 32], send_name: bool) -> Result<ClientConfig> {
    let t = rustls_client(spki_sha256, send_name, ALPN)?;
    let mut c = ClientConfig::new(Arc::new(QuicClientConfig::try_from(t)?));
    c.transport_config(transport());
    Ok(c)
}

/// Client TCP/TLS 1.3 configuration: same hybrid-PQ provider and SPKI pin, ALPN `http/1.1`.
pub fn tls_client_config(
    spki_sha256: [u8; 32],
    send_name: bool,
) -> Result<Arc<rustls::ClientConfig>> {
    Ok(Arc::new(rustls_client(spki_sha256, send_name, ALPN_TCP)?))
}

/// Server QUIC configuration: TLS 1.3, ALPN `h3`, the given ECDSA certificate (DER) and PKCS#8
/// key, no client certificate (a public web server asks for none).
pub fn server_config(cert: Vec<u8>, key: Vec<u8>) -> Result<ServerConfig> {
    server_config_clocked(cert, key, WireClock::from_env().is_some())
}

/// [`server_config`] for a chain whose client runs the wire clock (`clocked`) or not.
///
/// Under the clock the server sends with the fixed window too. Every acknowledgement the
/// client sends rides in a packet the clock holds for up to its look-ahead, while the
/// handshake (unpaced) set quinn's minimum RTT: BBR then sized its window from a 96 us
/// minimum against a 27 ms round trip, shrank it to 11 packets and never recovered, and the
/// downstream lost 96% of its datagrams (real-website re-run, 2026-11-15). The downstream's
/// rate is the carrier's, set by the signed class, as on plain WireGuard over UDP.
fn server_config_clocked(cert: Vec<u8>, key: Vec<u8>, clocked: bool) -> Result<ServerConfig> {
    let t = rustls_server(cert, key, ALPN)?;
    let mut s = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(t)?));
    s.transport_config(if clocked {
        clocked_transport()
    } else {
        transport()
    });
    Ok(s)
}

/// Server TCP/TLS 1.3 configuration: same certificate and key, ALPN `http/1.1` (or no ALPN).
pub fn tls_server_config(cert: Vec<u8>, key: Vec<u8>) -> Result<Arc<rustls::ServerConfig>> {
    let mut t = rustls_server(cert, key, ALPN_TCP)?;
    t.alpn_protocols = vec![ALPN_TCP.to_vec()];
    Ok(Arc::new(t))
}

/// Counters for the status file. Counts only: never an address.
#[derive(Debug, Default)]
pub struct Stats {
    /// A proven session is up.
    pub connected: AtomicBool,
    /// Proven sessions so far (QUIC + TCP/TLS).
    pub sessions: AtomicU64,
    /// Proven sessions that used the TCP/TLS 1.3 fallback.
    pub tcp_sessions: AtomicU64,
    /// Connections that never proved the key (web clients, probes).
    pub web_clients: AtomicU64,
    /// WireGuard datagrams sent to the peer.
    pub sent: AtomicU64,
    /// WireGuard datagrams received from the peer.
    pub received: AtomicU64,
    /// WireGuard datagrams dropped (no session, or the session refused them).
    pub dropped: AtomicU64,
    /// The wire clock's timing, when it is on (client only, RAM only).
    pub clock: ClockTrace,
    /// The QUIC path as this end's sender sees it (congestion window, round trip, losses),
    /// refreshed while datagrams flow: a stalled direction shows here, not in the counts.
    pub path: Mutex<Option<serde_json::Value>>,
}

impl Stats {
    /// Every [`PATH_EVERY`] datagrams, keep a snapshot of `c`'s path.
    fn note_path(&self, c: &Connection, n: u64) {
        if n.is_multiple_of(PATH_EVERY) {
            let p = c.stats().path;
            *self.path.lock().unwrap() = Some(serde_json::json!({
                "cwnd": p.cwnd,
                "rtt_us": p.rtt.as_micros() as u64,
                "min_rtt_us": p.min_rtt.as_micros() as u64,
                "congestion_events": p.congestion_events,
                "lost_packets": p.lost_packets,
                "sent_packets": p.sent_packets,
            }));
        }
    }
}

/// How often (in datagrams) the path snapshot is refreshed.
const PATH_EVERY: u64 = 256;

/// How the wire clock kept time: totals, and the same per 100 ms for the last two minutes,
/// so a measurement can line them up with its own windows (see `throughput_bench.py
/// --cpu-probe`). Recorded only while the experimental clock runs.
#[derive(Debug, Default)]
pub struct ClockTrace {
    buckets: Mutex<std::collections::VecDeque<ClockBucket>>,
    total: Mutex<ClockBucket>,
    queue_max: AtomicU64,
}

/// One 100 ms of the wire clock (CLOCK_MONOTONIC), or the totals.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ClockBucket {
    /// CLOCK_MONOTONIC / 100 ms (0 in the totals).
    pub at: u64,
    /// Slots given a datagram.
    pub fed: u64,
    /// Of those, decoys.
    pub decoys: u64,
    /// Slots skipped: the feeder was more than a step behind them.
    pub skipped: u64,
    /// Packets that reached the socket after their slot (sent at once).
    pub late: u64,
    /// The latest of those, in microseconds after its slot.
    pub late_max_us: u64,
    /// Full-size packets that found no slot waiting (sent at once).
    pub unslotted: u64,
}

/// Two minutes of 100 ms buckets.
const CLOCK_BUCKETS: usize = 1200;

impl ClockTrace {
    fn record(&self, now_ns: u64, f: impl Fn(&mut ClockBucket)) {
        let at = now_ns / 100_000_000;
        f(&mut self.total.lock().unwrap());
        let mut b = self.buckets.lock().unwrap();
        if b.back().is_none_or(|x| x.at != at) {
            if b.len() >= CLOCK_BUCKETS {
                b.pop_front();
            }
            b.push_back(ClockBucket {
                at,
                ..Default::default()
            });
        }
        f(b.back_mut().unwrap());
    }

    fn queue(&self, len: usize) {
        self.queue_max.fetch_max(len as u64, Ordering::Relaxed);
    }

    /// The totals and the trace, or `None` when the clock never ran.
    pub fn json(&self) -> Option<serde_json::Value> {
        let t = *self.total.lock().unwrap();
        if t == ClockBucket::default() {
            return None;
        }
        let row = |b: &ClockBucket| {
            [
                b.at,
                b.fed,
                b.decoys,
                b.skipped,
                b.late,
                b.late_max_us,
                b.unslotted,
            ]
        };
        Some(serde_json::json!({
            "fed": t.fed,
            "decoys": t.decoys,
            "skipped": t.skipped,
            "late": t.late,
            "late_max_us": t.late_max_us,
            "unslotted": t.unslotted,
            "slot_queue_max": self.queue_max.load(Ordering::Relaxed),
            "trace_columns": ["at_100ms", "fed", "decoys", "skipped", "late", "late_max_us", "unslotted"],
            "trace": self.buckets.lock().unwrap().iter().map(row).collect::<Vec<_>>(),
        }))
    }
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
            "tcp_sessions": n(&self.tcp_sessions),
            "web_clients": n(&self.web_clients),
            "sent": n(&self.sent),
            "received": n(&self.received),
            "dropped": n(&self.dropped),
            "clock": self.clock.json(),
            "path": self.path.lock().unwrap().clone(),
        })
    }
}

fn add(a: &AtomicU64) {
    a.fetch_add(1, Ordering::Relaxed);
}

/// Pack a WireGuard datagram into a fixed [`TCP_CELL_LEN`]-byte cell.
fn pack_cell(d: &[u8]) -> Result<[u8; TCP_CELL_LEN]> {
    ensure!(
        !d.is_empty() && d.len() <= CARRIER_DATAGRAM,
        "datagram out of bounds for TCP cell"
    );
    let mut cell = [0u8; TCP_CELL_LEN];
    cell[..2].copy_from_slice(&(d.len() as u16).to_be_bytes());
    cell[2..2 + d.len()].copy_from_slice(d);
    Ok(cell)
}

/// Answer as an HTTP/3 web origin: SETTINGS on a control stream, `200 OK` static HTML to every request.
async fn web(c: Connection) {
    // The control stream stays open for the connection's life, as HTTP/3 requires.
    let _control = match c.open_uni().await {
        Ok(mut s) => s.write_all(H3_CONTROL).await.ok().map(|_| s),
        Err(_) => None,
    };
    let reply = Arc::new(h3_decoy_response());
    while let Ok((mut send, mut recv)) = c.accept_bi().await {
        let reply = reply.clone();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(2), recv.read_to_end(16384)).await;
            if send.write_all(&reply).await.is_ok() {
                let _ = send.finish();
            }
        });
    }
}

/// Read unidirectional streams until one carries a valid proof for this connection,
/// returning which admitted key it matched. Every key is checked against every proof
/// attempt, so the comparison never reveals a member's position. Other streams (a
/// browser's control and QPACK streams) are drained and ignored.
async fn prove(c: &Connection, keys: &[[u8; TOKEN_LEN]]) -> Result<usize> {
    loop {
        let mut s = c.accept_uni().await?;
        let b = tokio::time::timeout(AUTH_WINDOW, s.read_to_end(64))
            .await
            .map_err(|_| anyhow!("slow stream"))?;
        if let Ok(b) = b
            && b.len() == TOKEN_STREAM.len() + TOKEN_LEN
            && b[..2] == TOKEN_STREAM
        {
            let mut found = None;
            let pq = quic_hybrid(c);
            for (k, key) in keys.iter().enumerate() {
                if equal(&b[2..], &proof(c, key)?) && pq {
                    found = Some(k);
                }
            }
            if let Some(k) = found {
                return Ok(k);
            }
        }
    }
}

/// Extract a 32-byte proof from an HTTP/1.1 request's `If-None-Match: "<64-hex>"` header.
pub(crate) fn parse_http_proof(req: &[u8]) -> Option<[u8; TOKEN_LEN]> {
    let text = std::str::from_utf8(req).ok()?;
    for line in text.lines() {
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("if-none-match")
        {
            let clean = value.trim().trim_matches('"');
            if clean.len() == TOKEN_LEN * 2 {
                let bytes = hex::decode(clean).ok()?;
                return bytes.try_into().ok();
            }
        }
    }
    None
}

/// Read an HTTP/1.1 request header up to `\r\n\r\n` (bounded to 4096 bytes).
async fn read_http_header<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while buf.len() < 4096 {
        let n = stream.read(&mut byte).await?;
        ensure!(n == 1, "EOF before end of HTTP header");
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(buf);
        }
    }
    anyhow::bail!("HTTP header too large")
}

/// Server: accept QUIC connections on `endpoint`; forward each proven session's datagrams to
/// WireGuard at `wireguard` and back over the session's own loopback socket. GotaTun
/// learns that socket as the member's peer endpoint, so replies are demultiplexed by
/// the carrier itself and members never receive each other's traffic. A reconnect with
/// the same key replaces only that member's older session (a roaming client).
pub async fn serve(
    endpoint: Endpoint,
    wireguard: SocketAddr,
    keys: Vec<[u8; TOKEN_LEN]>,
    stats: Arc<Stats>,
) -> Result<()> {
    serve_clocked(endpoint, wireguard, keys, stats, None).await
}

/// A relay's wire clock: the clock and the paced socket's slots
/// ([`clocked_server_endpoint`]).
#[derive(Clone)]
pub struct ServerClock {
    clock: WireClock,
    slots: Slots,
}

/// A server endpoint on `listen` whose downstream leaves on the wire clock: every member
/// session gets its own grid of `clock`'s slots, each filled with one datagram
/// (WireGuard's reply, or a decoy the client's WireGuard drops), released by the kernel
/// (`SO_TXTIME`, the `fq` qdisc on the egress link) whatever the relay's threads are doing.
pub fn clocked_server_endpoint(
    config: ServerConfig,
    listen: SocketAddr,
    clock: WireClock,
    stats: Arc<Stats>,
) -> Result<(Endpoint, ServerClock)> {
    let slots: Slots = Arc::default();
    let endpoint = paced_endpoint(listen, Some(config), slots.clone(), stats)?;
    Ok((endpoint, ServerClock { clock, slots }))
}

/// [`serve`], with the downstream on the wire clock when `clock` is given.
pub async fn serve_clocked(
    endpoint: Endpoint,
    wireguard: SocketAddr,
    keys: Vec<[u8; TOKEN_LEN]>,
    stats: Arc<Stats>,
    clock: Option<ServerClock>,
) -> Result<()> {
    ensure!(
        !keys.is_empty() && keys.len() <= 256,
        "one to 256 cloak keys"
    );
    let keys = Arc::new(keys);
    let current: Arc<Mutex<BTreeMap<usize, Connection>>> = Arc::default();
    while let Some(incoming) = endpoint.accept().await {
        let (keys, current, stats, clock) =
            (keys.clone(), current.clone(), stats.clone(), clock.clone());
        tokio::spawn(async move {
            let Ok(c) = incoming.await else {
                return;
            };
            tokio::spawn(web(c.clone()));
            let which = match tokio::time::timeout(AUTH_WINDOW, prove(&c, &keys)).await {
                Ok(Ok(k)) => k,
                _ => {
                    // Not ours: it stays an ordinary web client until it idles out.
                    add(&stats.web_clients);
                    return;
                }
            };
            if send_confirmation(&c, &keys[which]).await.is_err() {
                return;
            }
            add(&stats.sessions);
            // This session's private path to WireGuard.
            let Ok(udp) = UdpSocket::bind("127.0.0.1:0").await else {
                return;
            };
            if udp.connect(wireguard).await.is_err() {
                return;
            }
            let udp = Arc::new(udp);
            if let Some(old) = current.lock().unwrap().insert(which, c.clone()) {
                old.close(VarInt::from_u32(0x100), b"");
            }
            stats.connected.store(true, Ordering::Relaxed);
            // WireGuard's replies for this member reach only this session.
            let (replies, stats_down, conn_down) = (udp.clone(), stats.clone(), c.clone());
            let downlink = match clock.clone() {
                None => tokio::spawn(async move {
                    let mut buf = vec![0u8; 2048];
                    loop {
                        let Ok(n) = replies.recv(&mut buf).await else {
                            continue;
                        };
                        if conn_down
                            .send_datagram(Bytes::copy_from_slice(&buf[..n]))
                            .is_ok()
                        {
                            add(&stats_down.sent);
                            stats_down
                                .note_path(&conn_down, stats_down.sent.load(Ordering::Relaxed));
                        } else {
                            add(&stats_down.dropped);
                        }
                    }
                }),
                // On the clock: replies queue, and this session's feeder sends one datagram
                // per slot (a reply, or a decoy).
                Some(sc) => tokio::spawn(async move {
                    let queue: Arc<Mutex<std::collections::VecDeque<Bytes>>> = Arc::default();
                    // Bounded to ~150 ms of stream capacity to avoid stale-packet bufferbloat
                    // while absorbing short browser/QUIC bursts.
                    let cap = wire_clock_queue_cap(sc.clock.packets_per_second);
                    let (q_in, s_in, c_in) = (queue.clone(), stats_down.clone(), conn_down.clone());
                    let receive = async move {
                        let mut buf = vec![0u8; 2048];
                        loop {
                            let Ok(n) = replies.recv(&mut buf).await else {
                                continue;
                            };
                            {
                                let mut q = q_in.lock().unwrap();
                                if q.len() >= cap {
                                    q.pop_front();
                                    add(&s_in.dropped);
                                }
                                q.push_back(Bytes::copy_from_slice(&buf[..n]));
                            }
                            s_in.note_path(&c_in, s_in.sent.load(Ordering::Relaxed));
                        }
                    };
                    let tick = async move {
                        let (step, ahead) =
                            (sc.clock.step_ns(), sc.clock.lookahead.as_nanos() as u64);
                        let mut grid = None;
                        let mut timer =
                            tokio::time::interval(wire_clock_wake_interval(sc.clock.lookahead));
                        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                        loop {
                            timer.tick().await;
                            feed_step(
                                &conn_down,
                                step,
                                ahead,
                                &mut grid,
                                &queue,
                                &sc.slots,
                                &stats_down,
                            );
                        }
                    };
                    tokio::join!(receive, tick);
                }),
            };
            while let Ok(d) = c.read_datagram().await {
                if udp.send(&d).await.is_ok() {
                    add(&stats.received);
                }
            }
            downlink.abort();
            if let Some(sc) = &clock {
                // The session's grid ends with it: no stale slots for a later one.
                sc.slots.lock().unwrap().remove(&c.remote_address());
            }
            let mut cur = current.lock().unwrap();
            if cur
                .get(&which)
                .is_some_and(|x| x.stable_id() == c.stable_id())
            {
                cur.remove(&which);
            }
            stats.connected.store(!cur.is_empty(), Ordering::Relaxed);
        });
    }
    Ok(())
}

/// Server TCP/TLS 1.3 fallback listener on the same port (8443 behind nftables 443 redirect).
/// Unauthenticated requests receive [`http1_decoy_response`]; authenticated sessions switch
/// to fixed [`TCP_CELL_LEN`]-byte cell framing to `wireguard`. With `front`, streams from
/// loopback (the local I2P router's server tunnel) get [`FRONT_WINDOW`] to authenticate.
pub async fn serve_tcp(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    wireguard: SocketAddr,
    keys: Vec<[u8; TOKEN_LEN]>,
    stats: Arc<Stats>,
    front: bool,
) -> Result<()> {
    ensure!(
        !keys.is_empty() && keys.len() <= 256,
        "one to 256 cloak keys"
    );
    let keys = Arc::new(keys);
    let active_tcp: Arc<Mutex<BTreeMap<usize, (u64, tokio::task::AbortHandle)>>> = Arc::default();
    let seq = Arc::new(AtomicU64::new(1));
    loop {
        let (tcp, peer) = listener.accept().await?;
        let _ = tcp.set_nodelay(true);
        let window = if front && peer.ip().is_loopback() {
            FRONT_WINDOW
        } else {
            AUTH_WINDOW
        };
        let (acceptor, keys, active_tcp, stats, seq) = (
            acceptor.clone(),
            keys.clone(),
            active_tcp.clone(),
            stats.clone(),
            seq.clone(),
        );
        tokio::spawn(async move {
            let Ok(Ok(mut tls)) = tokio::time::timeout(window, acceptor.accept(tcp)).await else {
                return;
            };
            let Ok(Ok(header)) = tokio::time::timeout(window, read_http_header(&mut tls)).await
            else {
                add(&stats.web_clients);
                return;
            };
            let candidate = parse_http_proof(&header);
            let mut which = None;
            if let Some(cand) = candidate {
                for (k, key) in keys.iter().enumerate() {
                    if let Ok(expected) = tls_proof(tls.get_ref().1, key)
                        && equal(&cand, &expected)
                        && tls_hybrid(tls.get_ref().1)
                    {
                        which = Some(k);
                    }
                }
            }
            let Some(which) = which else {
                add(&stats.web_clients);
                let _ = tls.write_all(&http1_decoy_response()).await;
                let _ = tls.shutdown().await;
                return;
            };
            let Ok(confirmation) = tls_server_proof(tls.get_ref().1, &keys[which]) else {
                return;
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nCache-Control: no-store\r\nETag: \"{}\"\r\n\r\n",
                hex::encode(confirmation)
            );
            if tls.write_all(response.as_bytes()).await.is_err() {
                return;
            }
            add(&stats.sessions);
            add(&stats.tcp_sessions);
            let Ok(udp) = UdpSocket::bind("127.0.0.1:0").await else {
                return;
            };
            if udp.connect(wireguard).await.is_err() {
                return;
            }
            let udp = Arc::new(udp);
            stats.connected.store(true, Ordering::Relaxed);
            let (mut reader, mut writer) = tokio::io::split(tls);
            let (udp_down, stats_down) = (udp.clone(), stats.clone());
            let downlink = tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                loop {
                    let Ok(n) = udp_down.recv(&mut buf).await else {
                        break;
                    };
                    let Ok(cell) = pack_cell(&buf[..n]) else {
                        add(&stats_down.dropped);
                        continue;
                    };
                    if writer.write_all(&cell).await.is_ok() {
                        add(&stats_down.sent);
                    } else {
                        add(&stats_down.dropped);
                        break;
                    }
                }
            });
            let my_id = seq.fetch_add(1, Ordering::Relaxed);
            if let Some((_, old)) = active_tcp
                .lock()
                .unwrap()
                .insert(which, (my_id, downlink.abort_handle()))
            {
                old.abort();
            }
            let mut cell = [0u8; TCP_CELL_LEN];
            while reader.read_exact(&mut cell).await.is_ok() {
                let n = u16::from_be_bytes([cell[0], cell[1]]) as usize;
                if n == 0 {
                    continue;
                }
                if n > CARRIER_DATAGRAM {
                    break;
                }
                if udp.send(&cell[2..2 + n]).await.is_ok() {
                    add(&stats.received);
                }
            }
            downlink.abort();
            let mut act = active_tcp.lock().unwrap();
            if act.get(&which).is_some_and(|(id, _)| *id == my_id) {
                act.remove(&which);
            }
        });
    }
}

#[derive(Clone)]
enum ClientSink {
    Quic(Connection),
    Tcp(mpsc::Sender<Bytes>),
}

impl ClientSink {
    fn send(&self, d: Bytes) -> bool {
        match self {
            Self::Quic(c) => c.send_datagram(d).is_ok(),
            Self::Tcp(tx) => tx.try_send(d).is_ok(),
        }
    }
}

/// Client: take WireGuard's datagrams on `local` (only from `wireguard`), carry them to
/// the server at `remote` over QUIC/h3 (or TCP/TLS 1.3 when UDP is blocked), and hand the
/// replies back to `wireguard`. Reconnects forever and upgrades back to QUIC when UDP recovers.
/// With `front`, `remote` is the local I2P router's client tunnel: TCP/TLS 1.3 only, with
/// [`FRONT_WINDOW`], and never a QUIC attempt (I2P carries streams, not datagrams).
#[allow(clippy::too_many_arguments)]
pub async fn connect(
    local: SocketAddr,
    wireguard: SocketAddr,
    remote: SocketAddr,
    cover_name: Option<String>,
    spki_sha256: [u8; 32],
    key: [u8; TOKEN_LEN],
    stats: Arc<Stats>,
    front: bool,
) -> Result<()> {
    let clock = WireClock::from_env();
    connect_clocked(
        local,
        wireguard,
        remote,
        cover_name,
        spki_sha256,
        key,
        stats,
        front,
        clock,
    )
    .await
}

/// [`connect`] with the wire clock given (`None`: off).
#[allow(clippy::too_many_arguments)]
async fn connect_clocked(
    local: SocketAddr,
    wireguard: SocketAddr,
    remote: SocketAddr,
    cover_name: Option<String>,
    spki_sha256: [u8; 32],
    key: [u8; TOKEN_LEN],
    stats: Arc<Stats>,
    front: bool,
    clock: Option<WireClock>,
) -> Result<()> {
    let udp = Arc::new(UdpSocket::bind(local).await?);
    // The wire clock (experimental): only on QUIC, never with an I2P front (streams).
    let clock = clock.filter(|_| !front);
    let slots: Slots = Arc::default();
    let queue: Arc<Mutex<std::collections::VecDeque<Bytes>>> = Arc::default();
    let mut endpoint = match clock {
        Some(_) => paced_endpoint("0.0.0.0:0".parse()?, None, slots.clone(), stats.clone())?,
        None => Endpoint::client("0.0.0.0:0".parse()?)?,
    };
    let mut config = client_config(spki_sha256, cover_name.is_some())?;
    if clock.is_some() {
        config.transport_config(clocked_transport());
    }
    endpoint.set_default_client_config(config);
    let tls_connector = TlsConnector::from(tls_client_config(spki_sha256, cover_name.is_some())?);
    // Without a cover name no SNI is sent; the name below is then only a placeholder.
    let name = cover_name.unwrap_or_else(|| "localhost".into());
    let current: Arc<Mutex<Option<ClientSink>>> = Arc::default();
    let held: Arc<Mutex<Held>> = Arc::default();
    if let Some(clock) = clock {
        tokio::spawn(feed(
            clock,
            current.clone(),
            queue.clone(),
            slots.clone(),
            stats.clone(),
        ));
    }
    {
        let (udp, current, held, stats, queue) = (
            udp.clone(),
            current.clone(),
            held.clone(),
            stats.clone(),
            queue.clone(),
        );
        // Bounded to ~150 ms of stream capacity to eliminate 1-second FIFO bufferbloat.
        let cap = clock.map_or(0, |c| wire_clock_queue_cap(c.packets_per_second));
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
                    Some(ClientSink::Quic(_)) if clock.is_some() => {
                        // The feeder sends it in the next free slot.
                        let mut q = queue.lock().unwrap();
                        if q.len() >= cap {
                            q.pop_front();
                            add(&stats.dropped);
                        }
                        q.push_back(d);
                    }
                    Some(s) => {
                        if s.send(d) {
                            add(&stats.sent);
                        } else {
                            add(&stats.dropped);
                        }
                    }
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
        if front {
            let _ = tcp_session(
                &tls_connector,
                None,
                remote,
                &name,
                &key,
                &udp,
                wireguard,
                &current,
                &held,
                &stats,
                FRONT_WINDOW,
            )
            .await;
        } else if let Ok(Ok(c)) =
            tokio::time::timeout(QUIC_FALLBACK_TIMEOUT, endpoint.connect(remote, &name)?).await
        {
            let clock_q =
                clock.map(|cl| (queue.as_ref(), wire_clock_queue_cap(cl.packets_per_second)));
            if session(&c, &key, &udp, wireguard, &current, &held, clock_q, &stats)
                .await
                .is_err()
            {
                c.close(VarInt::from_u32(0), b"");
            }
        } else {
            let _ = tcp_session(
                &tls_connector,
                Some(&endpoint),
                remote,
                &name,
                &key,
                &udp,
                wireguard,
                &current,
                &held,
                &stats,
                AUTH_WINDOW,
            )
            .await;
        }
        *current.lock().unwrap() = None;
        stats.connected.store(false, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// The client's wire clock (busy-CPU fix, experimental: off unless `CPVPN_WIRE_CLOCK_PPS`
/// is set). On a busy CPU the carrier's packets left late or not at all, and their timing
/// traced the page's work (docs/evidence/WF_REAL_PILOT.json, CPU_LEAK_PROBE.json). With
/// the clock, the cloak owns departure: a feeder runs `lookahead` ahead of real time and
/// gives every slot of a fixed grid exactly one full-size datagram (WireGuard's, or a decoy
/// the first hop's WireGuard drops), and the paced socket stamps each packet with its slot
/// (`SO_TXTIME`) so the `fq` qdisc releases it on time whatever this thread is doing.
/// A stall shorter than `lookahead` leaves no trace on the wire. Limit: the first hop,
/// which decrypts this layer, still sees which slots carried WireGuard and which decoys.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WireClock {
    /// Slots per second: a little above the carrier's own rate, so its queue drains.
    pub packets_per_second: f64,
    /// How far ahead of real time slots are handed to the kernel.
    pub lookahead: Duration,
}

impl WireClock {
    /// From `CPVPN_WIRE_CLOCK_PPS` (the carrier's packets per second),
    /// `CPVPN_WIRE_CLOCK_MS` (look-ahead, default 30 ms), and optional
    /// `CPVPN_WIRE_CLOCK_HEADROOM` (default 1.05, range 1.01–1.25); `None` when unset or invalid.
    pub fn from_env() -> Option<Self> {
        let pps: f64 = std::env::var("CPVPN_WIRE_CLOCK_PPS").ok()?.parse().ok()?;
        let ms: u64 = std::env::var("CPVPN_WIRE_CLOCK_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);
        let headroom: f64 = std::env::var("CPVPN_WIRE_CLOCK_HEADROOM")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|v: &f64| v.is_finite() && (1.01..=1.25).contains(v))
            .unwrap_or(WIRE_CLOCK_HEADROOM);
        (pps.is_finite() && pps > 0.0 && (1..=500).contains(&ms)).then_some(Self {
            packets_per_second: pps * headroom,
            lookahead: Duration::from_millis(ms),
        })
    }

    fn step_ns(&self) -> u64 {
        (1e9 / self.packets_per_second) as u64
    }
}

/// The wire clock runs 5% faster than the carrier so bursts drain 2.5x faster than 1.02
/// while keeping the wire 100% constant-rate (spare slots carry identical full-size decoys).
const WIRE_CLOCK_HEADROOM: f64 = 1.05;

/// Feeder queue budget in seconds (~150 ms) to absorb short bursts without 1 s bufferbloat.
const WIRE_CLOCK_QUEUE_SECONDS: f64 = 0.15;

fn wire_clock_queue_cap(packets_per_second: f64) -> usize {
    ((packets_per_second * WIRE_CLOCK_QUEUE_SECONDS).ceil() as usize).max(64)
}

fn wire_clock_wake_interval(lookahead: Duration) -> Duration {
    (lookahead / 4).clamp(Duration::from_micros(500), Duration::from_millis(2))
}

/// A decoy: a full-size datagram whose first byte is no WireGuard message type, so the
/// first hop's WireGuard drops it silently (`try_into_wg`); full size so QUIC never packs
/// two into one packet.
fn decoy() -> Bytes {
    Bytes::from(vec![0u8; CARRIER_DATAGRAM])
}

/// CLOCK_MONOTONIC in nanoseconds: the clock `SO_TXTIME` and `fq` use.
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid timespec pointer for CLOCK_MONOTONIC.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Grid slots due before `horizon`, from slot `k` of a grid starting at `t0` with `step`.
/// Slots already more than one step in the past are skipped (a stall longer than the
/// look-ahead: those slots cannot be sent on time any more); returns the slots to feed and
/// the next `k`.
fn due_slots(t0: u64, step: u64, mut k: u64, now: u64, horizon: u64) -> (Vec<u64>, u64) {
    let mut out = Vec::new();
    if t0 + k * step + step < now {
        k = (now - t0) / step + 1;
    }
    while t0 + k * step < horizon {
        out.push(t0 + k * step);
        k += 1;
    }
    (out, k)
}

const SO_TXTIME: libc::c_int = 61;
const SCM_TXTIME: libc::c_int = SO_TXTIME;

/// Departure slots by destination: a client has one grid (its first hop), a relay one per
/// member session it serves.
type Slots = Arc<Mutex<std::collections::HashMap<SocketAddr, std::collections::VecDeque<u64>>>>;

/// quinn's UDP socket with departure times: every full-size packet (one carrying a
/// datagram) takes the next slot the feeder queued and leaves at that time; anything
/// else (an ACK-only packet) goes out at once through quinn's own socket.
#[derive(Debug)]
struct PacedSocket {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    fd: std::os::fd::OwnedFd,
    slots: Slots,
    stats: Arc<Stats>,
}

impl PacedSocket {
    fn send_at(&self, t: &quinn::udp::Transmit, at_ns: u64) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        let SocketAddr::V4(dst) = t.destination else {
            return Err(std::io::Error::other("the wire clock paces IPv4 only"));
        };
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: dst.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(*dst.ip()).to_be(),
            },
            sin_zero: [0; 8],
        };
        let mut iov = libc::iovec {
            iov_base: t.contents.as_ptr() as *mut libc::c_void,
            iov_len: t.contents.len(),
        };
        // SAFETY: CMSG_SPACE is a pure size computation.
        let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u64>() as u32) } as usize;
        let mut control = vec![0u8; space];
        // SAFETY: msghdr is plain data; every pointer below outlives the sendmsg call.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = &addr as *const _ as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = space as _;
        // SAFETY: the control buffer holds one cmsg of CMSG_SPACE(8) bytes.
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = SCM_TXTIME;
            (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u64>() as u32) as _;
            std::ptr::copy_nonoverlapping(&at_ns as *const u64 as *const u8, libc::CMSG_DATA(c), 8);
        }
        // SAFETY: a valid socket and msghdr.
        let n = unsafe { libc::sendmsg(self.fd.as_raw_fd(), &msg, libc::MSG_DONTWAIT) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

impl quinn::AsyncUdpSocket for PacedSocket {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, t: &quinn::udp::Transmit) -> std::io::Result<()> {
        if t.contents.len() >= OUTER_MTU as usize {
            let slot = self
                .slots
                .lock()
                .unwrap()
                .get_mut(&t.destination)
                .and_then(|q| q.pop_front());
            let now = monotonic_ns();
            match slot {
                Some(at) => {
                    let sent = self.send_at(t, at);
                    if sent.is_err() {
                        // Typically a full send buffer (packets waiting in fq count against
                        // it): quinn retries this packet, and it must keep its slot, or every
                        // retry would shift the rest of the grid one slot (measured: one in
                        // five packets then found no slot and left on quinn's timing).
                        self.slots
                            .lock()
                            .unwrap()
                            .entry(t.destination)
                            .or_default()
                            .push_front(at);
                    } else if at < now {
                        let us = (now - at) / 1_000;
                        self.stats.clock.record(now, |b| {
                            b.late += 1;
                            b.late_max_us = b.late_max_us.max(us);
                        });
                    }
                    return sent;
                }
                None => self.stats.clock.record(now, |b| b.unslotted += 1),
            }
        } else if let Some(&at) = self
            .slots
            .lock()
            .unwrap()
            .get(&t.destination)
            .and_then(|q| q.front())
        {
            // Align rare standalone control/ACK packets during an active clocked session to
            // the grid's next slot so they cannot fire at arrival-driven microsecond offsets.
            return self.send_at(t, at);
        }
        self.inner.try_send(t)
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

/// An endpoint on `bind` whose full-size packets leave at the slots in `slots` (a client's
/// with `server` None, a relay's with its server configuration).
fn paced_endpoint(
    bind: SocketAddr,
    server: Option<ServerConfig>,
    slots: Slots,
    stats: Arc<Stats>,
) -> Result<Endpoint> {
    use std::os::fd::{AsRawFd, OwnedFd};
    let socket = std::net::UdpSocket::bind(bind)?;
    let txtime = libc::sock_txtime {
        clockid: libc::CLOCK_MONOTONIC,
        flags: 0,
    };
    // SAFETY: a valid socket and a sock_txtime of the right size.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_TXTIME,
            &txtime as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::sock_txtime>() as libc::socklen_t,
        )
    };
    ensure!(rc == 0, "SO_TXTIME: {}", std::io::Error::last_os_error());
    // Packets the kernel holds for their departure time count against the send buffer:
    // ask for room for the whole look-ahead (the kernel caps it at net.core.wmem_max).
    let size: libc::c_int = 4 << 20;
    // SAFETY: a valid socket and an int option.
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &size as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    let fd = OwnedFd::from(socket.try_clone()?);
    let runtime = quinn::default_runtime().context("no async runtime for QUIC")?;
    let inner = runtime.wrap_udp_socket(socket)?;
    Ok(Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        server,
        Arc::new(PacedSocket {
            inner,
            fd,
            slots,
            stats,
        }),
        runtime,
    )?)
}

/// The wire clock's feeder: while a QUIC session is up, gives every slot due within the
/// look-ahead one datagram (WireGuard's oldest, or a decoy) and queues its slot for the
/// paced socket. A stall shorter than the look-ahead is caught up the moment it ends.
async fn feed(
    clock: WireClock,
    current: Arc<Mutex<Option<ClientSink>>>,
    queue: Arc<Mutex<std::collections::VecDeque<Bytes>>>,
    slots: Slots,
    stats: Arc<Stats>,
) {
    let (step, ahead) = (clock.step_ns(), clock.lookahead.as_nanos() as u64);
    let mut grid: Option<(u64, u64)> = None; // (t0, next k) of the current session
    let mut timer = tokio::time::interval(wire_clock_wake_interval(clock.lookahead));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        let sink = current.lock().unwrap().clone();
        match sink {
            Some(ClientSink::Quic(c)) => {
                feed_step(&c, step, ahead, &mut grid, &queue, &slots, &stats)
            }
            _ => {
                // No QUIC session (connecting, or the TCP fallback): a new session starts
                // a new grid with no stale slots.
                grid = None;
                slots.lock().unwrap().clear();
            }
        }
    }
}

/// One pass of a feeder for connection `c`: every slot of its grid due before the
/// look-ahead gets one datagram from `queue` (or a decoy), its slot queued for `c`'s
/// destination on the paced socket.
fn feed_step(
    c: &Connection,
    step: u64,
    ahead: u64,
    grid: &mut Option<(u64, u64)>,
    queue: &Mutex<std::collections::VecDeque<Bytes>>,
    slots: &Slots,
    stats: &Stats,
) {
    let dest = c.remote_address();
    let now = monotonic_ns();
    let (t0, k) = *grid.get_or_insert((now + ahead, 0));
    let (due, next) = due_slots(t0, step, k, now, now + ahead);
    let skipped = (next - k).saturating_sub(due.len() as u64);
    if skipped > 0 {
        stats.clock.record(now, |b| b.skipped += skipped);
    }
    *grid = Some((t0, next));
    stats.clock.queue(queue.lock().unwrap().len());
    for at in due {
        let d = queue.lock().unwrap().pop_front();
        let real = d.is_some();
        stats.clock.record(now, |b| {
            b.fed += 1;
            b.decoys += u64::from(!real);
        });
        slots.lock().unwrap().entry(dest).or_default().push_back(at);
        if c.send_datagram(d.unwrap_or_else(decoy)).is_ok() {
            if real {
                add(&stats.sent);
            }
        } else {
            if let Some(q) = slots.lock().unwrap().get_mut(&dest) {
                q.pop_back();
            }
            if real {
                add(&stats.dropped);
            }
        }
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

#[allow(clippy::too_many_arguments)]
async fn session(
    c: &Connection,
    key: &[u8; TOKEN_LEN],
    udp: &UdpSocket,
    wireguard: SocketAddr,
    current: &Mutex<Option<ClientSink>>,
    held: &Mutex<Held>,
    clock_queue: Option<(&Mutex<std::collections::VecDeque<Bytes>>, usize)>,
    stats: &Stats,
) -> Result<()> {
    ensure!(
        c.max_datagram_size().unwrap_or(0) >= CARRIER_DATAGRAM,
        "path too small for a WireGuard datagram"
    );
    ensure!(
        quic_hybrid(c),
        "cloak session without hybrid post-quantum key exchange"
    );
    let mut s = c.open_uni().await?;
    let mut msg = TOKEN_STREAM.to_vec();
    msg.extend_from_slice(&proof(c, key)?);
    s.write_all(&msg).await?;
    s.finish()?;
    tokio::time::timeout(AUTH_WINDOW, confirm_server(c, key))
        .await
        .context("server key confirmation timed out")??;
    // When the wire clock is active, enqueue held datagrams for the feeder instead of sending
    // them directly so session start/reconnect never emits an unslotted burst on the wire.
    if let Some((queue, cap)) = clock_queue {
        let mut q = queue.lock().unwrap();
        for d in held.lock().unwrap().take() {
            if q.len() >= cap {
                q.pop_front();
                add(&stats.dropped);
            }
            q.push_back(d);
        }
    } else {
        for d in held.lock().unwrap().take() {
            if c.send_datagram(d).is_ok() {
                add(&stats.sent);
            }
        }
    }
    *current.lock().unwrap() = Some(ClientSink::Quic(c.clone()));
    stats.connected.store(true, Ordering::Relaxed);
    add(&stats.sessions);
    loop {
        let d = c.read_datagram().await.context("session ended")?;
        if udp.send_to(&d, wireguard).await.is_ok() {
            add(&stats.received);
            stats.note_path(c, stats.received.load(Ordering::Relaxed));
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn tcp_session(
    connector: &TlsConnector,
    quic_endpoint: Option<&Endpoint>,
    remote: SocketAddr,
    name: &str,
    key: &[u8; TOKEN_LEN],
    udp: &UdpSocket,
    wireguard: SocketAddr,
    current: &Mutex<Option<ClientSink>>,
    held: &Mutex<Held>,
    stats: &Stats,
    window: Duration,
) -> Result<()> {
    let tcp = tokio::time::timeout(window, TcpStream::connect(remote)).await??;
    let _ = tcp.set_nodelay(true);
    let sni = ServerName::try_from(name.to_owned()).unwrap_or_else(|_| {
        ServerName::try_from("localhost".to_owned()).expect("valid placeholder SNI")
    });
    let mut tls = tokio::time::timeout(window, connector.connect(sni, tcp)).await??;
    ensure!(
        tls_hybrid(tls.get_ref().1),
        "cloak session without hybrid post-quantum key exchange"
    );
    let p = tls_proof(tls.get_ref().1, key)?;
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nIf-None-Match: \"{}\"\r\n\r\n",
        name,
        hex::encode(p)
    );
    tls.write_all(req.as_bytes()).await?;
    let resp = tokio::time::timeout(window, read_http_header(&mut tls)).await??;
    ensure!(
        resp.starts_with(b"HTTP/1.1 200 OK")
            && std::str::from_utf8(&resp)
                .unwrap_or("")
                .contains("application/octet-stream"),
        "TCP cloak proof rejected"
    );
    let confirmation = response_confirmation(&resp).context("server key confirmation missing")?;
    ensure!(
        equal(&confirmation, &tls_server_proof(tls.get_ref().1, key)?),
        "server key confirmation failed"
    );
    let (tx, mut rx) = mpsc::channel::<Bytes>(512);
    for d in held.lock().unwrap().take() {
        if tx.try_send(d).is_ok() {
            add(&stats.sent);
        }
    }
    *current.lock().unwrap() = Some(ClientSink::Tcp(tx));
    stats.connected.store(true, Ordering::Relaxed);
    add(&stats.sessions);
    add(&stats.tcp_sessions);
    let (mut reader, mut writer) = tokio::io::split(tls);
    let uplink = tokio::spawn(async move {
        while let Some(d) = rx.recv().await {
            let Ok(cell) = pack_cell(&d) else {
                continue;
            };
            if writer.write_all(&cell).await.is_err() {
                break;
            }
        }
    });
    let mut probe_interval = tokio::time::interval(QUIC_PROBE_INTERVAL);
    probe_interval.tick().await;
    let mut cell = [0u8; TCP_CELL_LEN];
    loop {
        tokio::select! {
            res = reader.read_exact(&mut cell) => {
                if res.is_err() {
                    break;
                }
                let n = u16::from_be_bytes([cell[0], cell[1]]) as usize;
                if n == 0 {
                    continue;
                }
                if n > CARRIER_DATAGRAM {
                    break;
                }
                if udp.send_to(&cell[2..2 + n], wireguard).await.is_ok() {
                    add(&stats.received);
                }
            }
            _ = probe_interval.tick(), if quic_endpoint.is_some() => {
                if let Some(Ok(connecting)) = quic_endpoint.map(|e| e.connect(remote, name))
                    && let Ok(Ok(c)) = tokio::time::timeout(Duration::from_secs(1), connecting).await
                {
                    c.close(VarInt::from_u32(0), b"upgrade");
                    break;
                }
            }
        }
    }
    uplink.abort();
    Ok(())
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
        server_with(key, false).await
    }

    /// A server cloak, with the clocked chain's transport when `clocked`.
    async fn server_with(key: [u8; 32], clocked: bool) -> (SocketAddr, UdpSocket, Arc<Stats>) {
        let (cert, k, _) = test_cert();
        let endpoint = Endpoint::server(
            server_config_clocked(cert, k, clocked).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stats = Arc::new(Stats::default());
        tokio::spawn(serve(
            endpoint,
            wg.local_addr().unwrap(),
            vec![key],
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
    async fn a_web_client_gets_decoy_html_and_reaches_nothing() {
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
        let reply = tokio::time::timeout(Duration::from_secs(3), recv.read_to_end(4096))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, h3_decoy_response());
        assert!(reply.starts_with(H3_DECOY_HEADERS));
        assert!(reply.ends_with(DECOY_HTML));
        let _ = c.send_datagram(Bytes::from_static(b"not a session"));
        assert!(nothing_arrives(&wg).await);
        tokio::time::sleep(AUTH_WINDOW).await;
        assert_eq!(stats.web_clients.load(Ordering::Relaxed), 1);
        assert_eq!(stats.sessions.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn tcp_fallback_carries_datagrams_when_udp_is_unavailable_and_serves_decoy_to_probes() {
        let (cert, k, pin) = test_cert();
        let key = [0x42; 32];
        // Bind ONLY a TCP listener (no UDP QUIC listener on that port -> simulates blocked UDP 443).
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(tls_server_config(cert, k).unwrap());
        let wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stats = Arc::new(Stats::default());
        tokio::spawn(serve_tcp(
            tcp_listener,
            acceptor,
            wg.local_addr().unwrap(),
            vec![key],
            stats.clone(),
            false,
        ));

        // 1. An unauthenticated HTTPS probe on TCP gets the 200 OK decoy HTML page.
        let connector = TlsConnector::from(tls_client_config(pin, true).unwrap());
        let tcp_probe = TcpStream::connect(addr).await.unwrap();
        let mut tls_probe = connector
            .connect(
                ServerName::try_from("cover.example".to_owned()).unwrap(),
                tcp_probe,
            )
            .await
            .unwrap();
        tls_probe
            .write_all(b"GET / HTTP/1.1\r\nHost: cover.example\r\n\r\n")
            .await
            .unwrap();
        let mut probe_reply = Vec::new();
        tls_probe.read_to_end(&mut probe_reply).await.unwrap();
        assert!(probe_reply.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(probe_reply.ends_with(DECOY_HTML));
        assert_eq!(stats.web_clients.load(Ordering::Relaxed), 1);

        // 2. The cloak client automatically falls back to TCP/TLS after UDP timeout and carries full datagrams.
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
            false,
        ));
        let mut buf = [0u8; 2048];
        let packet = vec![0x6b; CARRIER_DATAGRAM];
        let mut got = None;
        for _ in 0..60 {
            local_wg.send_to(&packet, local).await.unwrap();
            if let Ok(Ok((n, from))) =
                tokio::time::timeout(Duration::from_millis(100), wg.recv_from(&mut buf)).await
            {
                got = Some((n, from));
                break;
            }
        }
        let (n, from) = got.expect("TCP/TLS fallback delivers full-size WireGuard datagram");
        assert_eq!(&buf[..n], &packet[..]);
        wg.send_to(b"tcp-reply", from).await.unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), local_wg.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"tcp-reply");
        assert_eq!(stats.tcp_sessions.load(Ordering::Relaxed), 1);
        assert_eq!(cs.tcp_sessions.load(Ordering::Relaxed), 1);
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
            false,
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

    #[test]
    fn the_wire_clock_catches_up_a_short_stall_and_skips_a_long_one() {
        let (t0, step) = (1_000, 100);
        // On time: slots due before the horizon, in order.
        let (due, k) = due_slots(t0, step, 0, 1_000, 1_350);
        assert_eq!((due, k), (vec![1_000, 1_100, 1_200, 1_300], 4));
        // A stall shorter than the look-ahead: every missed slot is still fed, late, and the
        // paced socket sends each at its own time.
        let (due, k) = due_slots(t0, step, 4, 1_380, 1_730);
        assert_eq!((due, k), (vec![1_400, 1_500, 1_600, 1_700], 8));
        // A stall longer than the look-ahead: slots already in the past are skipped.
        let (due, k) = due_slots(t0, step, 8, 2_550, 2_900);
        assert_eq!((due, k), (vec![2_600, 2_700, 2_800], 19));
    }

    #[tokio::test]
    async fn a_clocked_relay_fills_every_downstream_slot_and_still_carries_wireguard() {
        // The relay's side of the clock: before WireGuard replies at all, the client's
        // WireGuard already receives one full-size decoy per slot; a reply takes a slot
        // and arrives intact. The client here is not clocked, so only the relay's clock
        // can produce these.
        let (cert, k, pin) = test_cert();
        let key = [6; 32];
        let clock = WireClock {
            packets_per_second: 500.0,
            lookahead: Duration::from_millis(20),
        };
        let ss = Arc::new(Stats::default());
        let (endpoint, sc) = clocked_server_endpoint(
            server_config_clocked(cert, k, true).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            clock,
            ss.clone(),
        )
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        tokio::spawn(serve_clocked(
            endpoint,
            wg.local_addr().unwrap(),
            vec![key],
            ss.clone(),
            Some(sc),
        ));
        let local_wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local: SocketAddr = probe.local_addr().unwrap();
        drop(probe);
        let cs = Arc::new(Stats::default());
        tokio::spawn(connect_clocked(
            local,
            local_wg.local_addr().unwrap(),
            addr,
            Some("cover.example".into()),
            pin,
            key,
            cs.clone(),
            false,
            None,
        ));
        let mut buf = [0u8; 2048];
        let first = tokio::time::timeout(Duration::from_secs(5), local_wg.recv_from(&mut buf))
            .await
            .expect("the relay's clock sends as soon as the session is up")
            .unwrap();
        assert_eq!(
            (first.0, buf[0]),
            (CARRIER_DATAGRAM, 0),
            "a full-size decoy"
        );
        let start = std::time::Instant::now();
        let mut decoys = 0;
        while start.elapsed() < Duration::from_secs(1) {
            if let Ok(Ok((n, _))) =
                tokio::time::timeout(Duration::from_millis(100), local_wg.recv_from(&mut buf)).await
            {
                assert_eq!((n, buf[0]), (CARRIER_DATAGRAM, 0));
                decoys += 1;
            }
        }
        assert!(
            (400..=600).contains(&decoys),
            "one decoy per downstream slot, about 500/s: {decoys}"
        );
        // Upstream once, so the relay's WireGuard learns this session's socket; its reply
        // takes the next downstream slot.
        local_wg.send_to(&[0x01; 148], local).await.unwrap();
        let (_, session) = tokio::time::timeout(Duration::from_secs(2), wg.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let reply = vec![0x04; CARRIER_DATAGRAM];
        wg.send_to(&reply, session).await.unwrap();
        let mut found = false;
        for _ in 0..200 {
            let (n, _) = tokio::time::timeout(Duration::from_secs(1), local_wg.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            if buf[0] != 0 {
                assert_eq!(&buf[..n], &reply[..]);
                found = true;
                break;
            }
        }
        assert!(found, "WireGuard's reply was carried among the decoys");
        let c = ss.clock.json().expect("the relay's clock ran");
        let (fed, decoys) = (c["fed"].as_u64().unwrap(), c["decoys"].as_u64().unwrap());
        assert!(
            fed >= 500 && decoys == fed - 1,
            "fed {fed}, decoys {decoys}"
        );
        assert_eq!(ss.sent.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn the_wire_clock_fills_every_slot_and_still_carries_wireguard() {
        let (_, _, pin) = test_cert();
        let key = [5; 32];
        let (addr, wg, _) = server(key).await;
        let local_wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local: SocketAddr = probe.local_addr().unwrap();
        drop(probe);
        let clock = WireClock {
            packets_per_second: 500.0,
            lookahead: Duration::from_millis(20),
        };
        let cs = Arc::new(Stats::default());
        tokio::spawn(connect_clocked(
            local,
            local_wg.local_addr().unwrap(),
            addr,
            Some("cover.example".into()),
            pin,
            key,
            cs.clone(),
            false,
            Some(clock),
        ));
        let mut buf = [0u8; 2048];
        // Wait for the session; then, with nothing from WireGuard, only decoys arrive.
        let first = tokio::time::timeout(Duration::from_secs(5), wg.recv_from(&mut buf))
            .await
            .expect("the clock sends as soon as the session is up")
            .unwrap();
        assert_eq!(
            (first.0, buf[0]),
            (CARRIER_DATAGRAM, 0),
            "a full-size decoy"
        );
        let start = std::time::Instant::now();
        let mut decoys = 0;
        while start.elapsed() < Duration::from_secs(1) {
            if let Ok(Ok((n, _))) =
                tokio::time::timeout(Duration::from_millis(100), wg.recv_from(&mut buf)).await
            {
                assert_eq!((n, buf[0]), (CARRIER_DATAGRAM, 0));
                decoys += 1;
            }
        }
        assert!(
            (400..=600).contains(&decoys),
            "one decoy per slot, about 500/s: {decoys}"
        );
        // A real WireGuard datagram takes the next slot and arrives intact.
        let packet = vec![0x04; CARRIER_DATAGRAM];
        local_wg.send_to(&packet, local).await.unwrap();
        let mut found = false;
        for _ in 0..200 {
            let (n, _) = tokio::time::timeout(Duration::from_secs(1), wg.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            if buf[0] != 0 {
                assert_eq!(&buf[..n], &packet[..]);
                found = true;
                break;
            }
        }
        assert!(found, "WireGuard's datagram was carried among the decoys");
        assert_eq!(cs.sent.load(Ordering::Relaxed), 1);
        // The clock reports what it did: every slot fed, all but one a decoy.
        let c = cs.clock.json().expect("the clock ran");
        let (fed, decoys) = (c["fed"].as_u64().unwrap(), c["decoys"].as_u64().unwrap());
        assert!(
            fed >= 500 && decoys == fed - 1,
            "fed {fed}, decoys {decoys}"
        );
        assert!(!c["trace"].as_array().unwrap().is_empty());
    }

    /// Under fq (which holds packets until their slot), a clocked session at the `fast` rate
    /// with traffic both ways keeps nearly every packet on its slot. Before the fix, packets
    /// held in fq filled the send buffer, every failed send lost its slot, and one packet in
    /// seven then left on quinn's timing (2,453 in 4 s). Needs fq on loopback, so it runs
    /// in its own network namespace (CI: `unshare -Urn`, see verify.yml):
    ///   ip link set lo up; tc qdisc replace dev lo root fq; cargo test ... -- --ignored
    #[tokio::test]
    #[ignore]
    async fn the_clock_keeps_every_packet_on_its_slot_under_fq() {
        let (_, _, pin) = test_cert();
        let key = [6; 32];
        let (addr, wg, _) = server(key).await;
        let local_wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local: SocketAddr = probe.local_addr().unwrap();
        drop(probe);
        let clock = WireClock {
            packets_per_second: 4080.0,
            lookahead: Duration::from_millis(30),
        };
        let cs = Arc::new(Stats::default());
        tokio::spawn(connect_clocked(
            local,
            local_wg.local_addr().unwrap(),
            addr,
            Some("cover.example".into()),
            pin,
            key,
            cs.clone(),
            false,
            Some(clock),
        ));
        let mut buf = [0u8; 2048];
        let (_, from) = tokio::time::timeout(Duration::from_secs(5), wg.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let wg = Arc::new(wg);
        // Downstream: the server side sends 4,000 datagrams/s back, as a real carrier does.
        let down = {
            let wg = wg.clone();
            tokio::spawn(async move {
                let mut t = tokio::time::interval(Duration::from_micros(250));
                let p = vec![0x04; CARRIER_DATAGRAM];
                loop {
                    t.tick().await;
                    let _ = wg.send_to(&p, from).await;
                }
            })
        };
        let drain = tokio::spawn(async move {
            let mut b = [0u8; 2048];
            loop {
                let _ = wg.recv_from(&mut b).await;
            }
        });
        tokio::time::sleep(Duration::from_secs(4)).await;
        down.abort();
        drain.abort();
        let c = cs.clock.json().unwrap();
        let (fed, unslotted) = (c["fed"].as_u64().unwrap(), c["unslotted"].as_u64().unwrap());
        println!(
            "fed {fed} unslotted {unslotted} late {} skipped {}",
            c["late"], c["skipped"]
        );
        assert!(fed > 12_000, "the clock ran at the fast rate: {fed}");
        assert!(
            unslotted * 100 < fed,
            "{unslotted} of {fed} packets left without their slot"
        );
    }

    /// The relay's clock under fq too: client and relay both clocked at the `fast` rate,
    /// traffic both ways; each end keeps nearly every full-size packet on its slot. Runs
    /// with the test above (CI's filter is the common prefix).
    #[tokio::test]
    #[ignore]
    async fn the_clock_keeps_every_packet_on_its_slot_under_fq_both_ways() {
        let (cert, k, pin) = test_cert();
        let key = [8; 32];
        let clock = WireClock {
            packets_per_second: 4080.0,
            lookahead: Duration::from_millis(30),
        };
        let ss = Arc::new(Stats::default());
        let (endpoint, sc) = clocked_server_endpoint(
            server_config_clocked(cert, k, true).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            clock,
            ss.clone(),
        )
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        tokio::spawn(serve_clocked(
            endpoint,
            wg.local_addr().unwrap(),
            vec![key],
            ss.clone(),
            Some(sc),
        ));
        let local_wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local: SocketAddr = probe.local_addr().unwrap();
        drop(probe);
        let cs = Arc::new(Stats::default());
        tokio::spawn(connect_clocked(
            local,
            local_wg.local_addr().unwrap(),
            addr,
            Some("cover.example".into()),
            pin,
            key,
            cs.clone(),
            false,
            Some(clock),
        ));
        // The client's WireGuard speaks first, so the relay's WireGuard learns the session.
        let mut buf = [0u8; 2048];
        let packet = vec![0x04; CARRIER_DATAGRAM];
        let mut from = None;
        for _ in 0..100 {
            local_wg.send_to(&packet, local).await.unwrap();
            if let Ok(Ok((_, f))) =
                tokio::time::timeout(Duration::from_millis(100), wg.recv_from(&mut buf)).await
                && buf[0] != 0
            {
                from = Some(f);
                break;
            }
        }
        let from = from.expect("the session came up");
        let (wg, local_wg) = (Arc::new(wg), Arc::new(local_wg));
        let pump = |sock: Arc<UdpSocket>, to: SocketAddr| {
            tokio::spawn(async move {
                let mut t = tokio::time::interval(Duration::from_micros(250));
                let p = vec![0x04; CARRIER_DATAGRAM];
                loop {
                    t.tick().await;
                    let _ = sock.send_to(&p, to).await;
                }
            })
        };
        let drain = |sock: Arc<UdpSocket>| {
            tokio::spawn(async move {
                let mut b = [0u8; 2048];
                loop {
                    let _ = sock.recv_from(&mut b).await;
                }
            })
        };
        let tasks = [
            pump(wg.clone(), from),
            pump(local_wg.clone(), local),
            drain(wg.clone()),
            drain(local_wg.clone()),
        ];
        tokio::time::sleep(Duration::from_secs(4)).await;
        for t in tasks {
            t.abort();
        }
        for (end, s) in [("client", &cs), ("relay", &ss)] {
            let c = s.clock.json().unwrap();
            let (fed, unslotted) = (c["fed"].as_u64().unwrap(), c["unslotted"].as_u64().unwrap());
            println!(
                "{end}: fed {fed} unslotted {unslotted} late {} skipped {}",
                c["late"], c["skipped"]
            );
            assert!(fed > 12_000, "{end}: the clock ran at the fast rate: {fed}");
            assert!(
                unslotted * 100 < fed,
                "{end}: {unslotted} of {fed} packets left without their slot"
            );
        }
    }

    /// Datagrams per second that reach the client's WireGuard while the server side sends
    /// 4,000/s for `secs` seconds, with the client's wire clock on or off; and the server's
    /// counters.
    async fn downstream_per_second(
        clock: Option<WireClock>,
        clocked_server: bool,
        secs: u64,
    ) -> (Vec<u64>, Arc<Stats>) {
        let (_, _, pin) = test_cert();
        let key = [7; 32];
        let (addr, wg, server_stats) = server_with(key, clocked_server).await;
        let local_wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local: SocketAddr = probe.local_addr().unwrap();
        drop(probe);
        let cs = Arc::new(Stats::default());
        tokio::spawn(connect_clocked(
            local,
            local_wg.local_addr().unwrap(),
            addr,
            Some("cover.example".into()),
            pin,
            key,
            cs.clone(),
            false,
            clock,
        ));
        // The client's WireGuard speaks first (as a handshake does), so the server learns it.
        let mut buf = [0u8; 2048];
        let packet = vec![0x04; CARRIER_DATAGRAM];
        let mut from = None;
        for _ in 0..100 {
            local_wg.send_to(&packet, local).await.unwrap();
            if let Ok(Ok((_, f))) =
                tokio::time::timeout(Duration::from_millis(100), wg.recv_from(&mut buf)).await
            {
                from = Some(f);
                break;
            }
        }
        let from = from.expect("the session came up");
        let wg = Arc::new(wg);
        let down = {
            let wg = wg.clone();
            tokio::spawn(async move {
                let mut t = tokio::time::interval(Duration::from_micros(250));
                let p = vec![0x04; CARRIER_DATAGRAM];
                loop {
                    t.tick().await;
                    let _ = wg.send_to(&p, from).await;
                }
            })
        };
        let drain = tokio::spawn(async move {
            let mut b = [0u8; 2048];
            loop {
                let _ = wg.recv_from(&mut b).await;
            }
        });
        let mut per_second = Vec::new();
        for _ in 0..secs {
            let end = tokio::time::Instant::now() + Duration::from_secs(1);
            let mut n = 0;
            while let Ok(Ok(_)) = tokio::time::timeout_at(end, local_wg.recv_from(&mut buf)).await {
                n += 1;
            }
            per_second.push(n);
        }
        down.abort();
        drain.abort();
        (per_second, server_stats)
    }

    /// The server of a clocked chain sends its downstream with the fixed window. With BBR,
    /// the clock's held-back acknowledgements (27 ms round trip against the unpaced
    /// handshake's 81 us minimum) shrank the relay's window to 8-11 packets within 20 s
    /// and it never grew back: the client got 4% of the downstream, its carrier restarted
    /// every 10 s, and 1 page load in 8 worked (8 in 8 with the fixed window, same lab).
    #[tokio::test]
    async fn a_clocked_chains_server_never_shrinks_its_window() {
        let clock = WireClock {
            packets_per_second: 4080.0,
            lookahead: Duration::from_millis(30),
        };
        let (per_second, server) = downstream_per_second(Some(clock), true, 3).await;
        let path = server
            .path
            .lock()
            .unwrap()
            .clone()
            .expect("the server noted its path");
        assert_eq!(path["cwnd"], FIXED_WINDOW, "server path: {path}");
        let got: u64 = per_second.iter().sum();
        assert!(
            got > 3_000,
            "the downstream reached the client: {per_second:?}"
        );
    }

    #[test]
    fn the_clocked_transport_never_holds_or_paces_a_datagram() {
        use quinn::congestion::ControllerFactory;
        let mut c = Arc::new(FixedWindow).build(std::time::Instant::now(), OUTER_MTU);
        // Above u32::MAX quinn turns its pacer off (quinn-proto pacing.rs); and no event
        // may shrink the window, or BBR's behaviour would come back.
        assert!(c.window() > u64::from(u32::MAX));
        let now = std::time::Instant::now();
        c.on_congestion_event(now, now, true, 1 << 20);
        c.on_mtu_update(1200);
        assert_eq!(
            (c.window(), c.initial_window()),
            (FIXED_WINDOW, FIXED_WINDOW)
        );
    }

    #[test]
    fn the_clock_trace_keeps_100_ms_buckets_for_two_minutes() {
        let t = ClockTrace::default();
        assert!(
            t.json().is_none(),
            "nothing to report before the clock runs"
        );
        t.record(1_000_000_000, |b| b.fed += 1);
        t.record(1_050_000_000, |b| b.late += 1);
        t.record(1_150_000_000, |b| b.skipped += 3);
        let j = t.json().unwrap();
        assert_eq!(
            (j["fed"].as_u64(), j["late"].as_u64(), j["skipped"].as_u64()),
            (Some(1), Some(1), Some(3))
        );
        let trace = j["trace"].as_array().unwrap();
        assert_eq!(trace.len(), 2, "two 100 ms buckets");
        assert_eq!(trace[0][0].as_u64(), Some(10));
        for k in 0..2_000u64 {
            t.record(2_000_000_000 + k * 100_000_000, |b| b.fed += 1);
        }
        assert_eq!(
            t.json().unwrap()["trace"].as_array().unwrap().len(),
            CLOCK_BUCKETS
        );
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

    /// A client that offers only classical X25519 (a downgraded or non-PQ peer): it still
    /// completes the handshake and sees the decoy, but the right proof earns it no tunnel.
    async fn classical(addr: SocketAddr, pin: [u8; 32]) -> (Endpoint, Connection) {
        let mut p = aws_lc_rs::default_provider();
        p.kx_groups = vec![aws_lc_rs::kx_group::X25519];
        let p = Arc::new(p);
        let mut t = rustls::ClientConfig::builder_with_provider(p.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Pinned {
                spki_sha256: pin,
                provider: p,
            }))
            .with_no_client_auth();
        t.alpn_protocols = vec![ALPN.to_vec()];
        let mut c = ClientConfig::new(Arc::new(QuicClientConfig::try_from(t).unwrap()));
        c.transport_config(transport());
        let mut e = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        e.set_default_client_config(c);
        let c = e.connect(addr, "cover.example").unwrap().await.unwrap();
        (e, c)
    }

    #[tokio::test]
    async fn a_classical_key_exchange_never_becomes_a_tunnel() {
        let (_, _, pin) = test_cert();
        let key = [5; 32];
        let (addr, wg, stats) = server(key).await;
        let (_e1, old) = classical(addr, pin).await;
        assert!(!quic_hybrid(&old));
        send_proof(&old, proof(&old, &key).unwrap()).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = old.send_datagram(Bytes::from_static(b"let me in"));
        assert!(nothing_arrives(&wg).await);
        assert_eq!(stats.sessions.load(Ordering::Relaxed), 0);
        // The cloak's own client negotiates the hybrid group and gets its tunnel.
        let (_e2, pq) = raw(addr, pin).await.unwrap();
        assert!(quic_hybrid(&pq));
        send_proof(&pq, proof(&pq, &key).unwrap()).await;
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

    /// A TCP relay standing in for an I2P tunnel: it holds the client's first bytes for
    /// `delay` (as a stream setup across I2P does) before passing anything through.
    async fn slow_relay(to: SocketAddr, delay: Duration) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut a, _)) = l.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    // Connected at once, so both ends' handshake clocks run during the hold.
                    let Ok(mut b) = TcpStream::connect(to).await else {
                        return;
                    };
                    let mut first = vec![0u8; 4096];
                    let Ok(n) = a.read(&mut first).await else {
                        return;
                    };
                    tokio::time::sleep(delay).await;
                    if b.write_all(&first[..n]).await.is_err() {
                        return;
                    }
                    let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
                });
            }
        });
        at
    }

    #[tokio::test]
    async fn a_front_client_uses_only_tcp_and_survives_a_slow_tunnel() {
        let (cert, k, pin) = test_cert();
        let key = [0x24; 32];
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(tls_server_config(cert, k).unwrap());
        let wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stats = Arc::new(Stats::default());
        tokio::spawn(serve_tcp(
            tcp_listener,
            acceptor,
            wg.local_addr().unwrap(),
            vec![key],
            stats.clone(),
            true,
        ));
        // Longer than AUTH_WINDOW: only the front's window lets this handshake finish.
        let tunnel = slow_relay(addr, AUTH_WINDOW + Duration::from_secs(2)).await;
        // Anything sent to the tunnel's port over UDP would be a QUIC attempt.
        let quic_watch = UdpSocket::bind(tunnel).await.unwrap();
        let local_wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local: SocketAddr = probe.local_addr().unwrap();
        drop(probe);
        let cs = Arc::new(Stats::default());
        tokio::spawn(connect(
            local,
            local_wg.local_addr().unwrap(),
            tunnel,
            None,
            pin,
            key,
            cs.clone(),
            true,
        ));
        let mut buf = [0u8; 2048];
        let packet = vec![0x5a; CARRIER_DATAGRAM];
        let mut got = None;
        for _ in 0..150 {
            local_wg.send_to(&packet, local).await.unwrap();
            if let Ok(Ok((n, _))) =
                tokio::time::timeout(Duration::from_millis(100), wg.recv_from(&mut buf)).await
            {
                got = Some(n);
                break;
            }
        }
        assert_eq!(
            got,
            Some(CARRIER_DATAGRAM),
            "the front session carries datagrams"
        );
        assert_eq!(cs.tcp_sessions.load(Ordering::Relaxed), 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), quic_watch.recv_from(&mut buf))
                .await
                .is_err(),
            "a front client never tries QUIC"
        );
    }

    /// A UDP path between `client` and `server`: `delay` one way, and server->client
    /// packets dropped while `lossy` says so (by packet index). Returns the address the
    /// client should dial.
    async fn lossy_path(server: SocketAddr, delay: Duration, lossy: fn(u64) -> bool) -> SocketAddr {
        let outside = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let inside = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let at = outside.local_addr().unwrap();
        let client = Arc::new(std::sync::Mutex::new(None::<SocketAddr>));
        let (o, i, c) = (outside.clone(), inside.clone(), client.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            while let Ok((n, from)) = o.recv_from(&mut buf).await {
                *c.lock().unwrap() = Some(from);
                let (i, b) = (i.clone(), buf[..n].to_vec());
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = i.send_to(&b, server).await;
                });
            }
        });
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let mut index = 0u64;
            while let Ok((n, _)) = inside.recv_from(&mut buf).await {
                index += 1;
                let Some(to) = *client.lock().unwrap() else {
                    continue;
                };
                if lossy(index) {
                    continue;
                }
                let (o, b) = (outside.clone(), buf[..n].to_vec());
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = o.send_to(&b, to).await;
                });
            }
        });
        at
    }

    /// Regression (KVM stall, 14 Nov 2026): after a burst of early losses the sender's
    /// window must recover, so a steady datagram stream keeps flowing. With loss-based
    /// NewReno the window collapsed and datagram sends stalled.
    #[tokio::test]
    async fn datagram_flow_recovers_after_early_losses() {
        let (cert, k, pin) = test_cert();
        let server = Endpoint::server(
            server_config(cert, k).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        // 20 ms each way; every 3rd server->client packet among the first 300 is lost.
        let path = lossy_path(
            server.local_addr().unwrap(),
            Duration::from_millis(20),
            |i| i <= 300 && i % 3 == 0,
        )
        .await;
        let accept = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            (server, conn)
        });
        let (_ce, client) = raw(path, pin).await.unwrap();
        let (_se, conn) = accept.await.unwrap();
        // The server streams carrier-sized datagrams at 500/s (about 4.6 Mbit/s) for 4 s.
        let sender = tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(2));
            for _ in 0..2000 {
                tick.tick().await;
                let _ = conn.send_datagram(Bytes::from(vec![0x33; CARRIER_DATAGRAM]));
            }
            conn
        });
        let start = tokio::time::Instant::now();
        let mut late = 0u32;
        while start.elapsed() < Duration::from_secs(4) {
            let got =
                tokio::time::timeout(Duration::from_millis(200), client.read_datagram()).await;
            if matches!(got, Ok(Ok(_))) && start.elapsed() >= Duration::from_secs(2) {
                late += 1;
            }
        }
        let _conn = sender.await.unwrap();
        // The last 2 s offered about 1000 datagrams on a clean path.
        assert!(
            late >= 800,
            "only {late} of ~1000 datagrams arrived once the losses had stopped"
        );
    }
    #[test]
    fn formal_v2_proof_vectors_match_the_symbolic_model_inputs() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tools/testdata/formal/cloak-v2.json")).unwrap();
        assert_eq!(
            vectors["exporter_label"],
            std::str::from_utf8(EXPORTER_LABEL).unwrap()
        );
        assert_eq!(
            vectors["model_sha256"],
            hex::encode(Sha256::digest(include_bytes!(
                "../formal/cloak/cloak.spthy"
            )))
        );
        let key: [u8; TOKEN_LEN] = hex::decode(vectors["key_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let exporter: [u8; 32] = hex::decode(vectors["exporter_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        for row in vectors["roles"].as_array().unwrap() {
            let role = row["role"].as_str().unwrap().as_bytes();
            let message = hex::decode(row["message_hex"].as_str().unwrap()).unwrap();
            let expected = row["proof_hex"].as_str().unwrap();
            assert_eq!(hex::encode(role_proof(&key, &exporter, role)), expected);
            assert_eq!(hex::encode(hmac_sha256(&key, &message)), expected);
        }
    }

    #[test]
    fn audit_v2_proofs_are_role_key_and_exporter_separated() {
        let key = [7; TOKEN_LEN];
        let exporter = [8; 32];
        let c = role_proof(&key, &exporter, b"client");
        assert_ne!(c, role_proof(&key, &exporter, b"server"));
        assert_ne!(c, role_proof(&[9; TOKEN_LEN], &exporter, b"client"));
        assert_ne!(c, role_proof(&key, &[9; 32], b"client"));
        assert_ne!(
            TOKEN_STREAM,
            [0x40, 0x7e],
            "legacy proof stream must not authenticate"
        );
    }

    #[test]
    fn audit_tcp_requires_one_well_formed_server_confirmation() {
        let p = [7u8; TOKEN_LEN];
        let head = format!("HTTP/1.1 200 OK\r\nETag: \"{}\"\r\n\r\n", hex::encode(p));
        assert_eq!(response_confirmation(head.as_bytes()), Some(p));
        assert_eq!(response_confirmation(b"HTTP/1.1 200 OK\r\n\r\n"), None);
        let duplicate = format!(
            "HTTP/1.1 200 OK\r\nETag: \"{}\"\r\nETag: \"{}\"\r\n\r\n",
            hex::encode(p),
            hex::encode(p)
        );
        assert_eq!(response_confirmation(duplicate.as_bytes()), None);
        assert_eq!(
            response_confirmation(b"HTTP/1.1 200 OK\r\nETag: not-a-tag\r\n\r\n"),
            None
        );
        let (cert, key, _) = test_cert();
        assert_eq!(
            tls_server_config(cert, key).unwrap().alpn_protocols,
            vec![ALPN_TCP.to_vec()]
        );
    }

    async fn audit_untrusted_server_confirmation(mode: u8) {
        let (cert, k, pin) = test_cert();
        let endpoint = Endpoint::server(
            server_config(cert, k).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let key = [7; TOKEN_LEN];
        let fake = tokio::spawn(async move {
            let c = endpoint.accept().await.unwrap().await.unwrap();
            // Receive the real client's proof; possessing a TLS identity is insufficient.
            let mut request = c.accept_uni().await.unwrap();
            let raw = request.read_to_end(64).await.unwrap();
            if mode != 0 {
                let mut stream = c.open_uni().await.unwrap();
                stream.write_all(&SERVER_CONFIRM_STREAM).await.unwrap();
                let tag = if mode == 1 {
                    raw[2..].try_into().unwrap()
                } else {
                    server_proof(&c, &[9; TOKEN_LEN]).unwrap()
                };
                stream.write_all(&tag).await.unwrap();
                stream.finish().unwrap();
            }
            let leaked = tokio::time::timeout(Duration::from_millis(600), c.read_datagram()).await;
            assert!(
                leaked.is_err(),
                "client leaked a held datagram before server authentication"
            );
            endpoint.close(0u32.into(), b"test ended");
        });
        let (_client, c) = raw(addr, pin).await.unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wireguard = udp.local_addr().unwrap();
        let current = Mutex::new(None);
        let held = Mutex::new(Held::default());
        held.lock()
            .unwrap()
            .push(Bytes::from_static(b"must-not-leak"));
        let stats = Stats::default();
        let result = session(&c, &key, &udp, wireguard, &current, &held, None, &stats).await;
        assert!(result.is_err());
        assert!(!stats.connected.load(Ordering::Relaxed));
        assert_eq!(stats.sessions.load(Ordering::Relaxed), 0);
        assert!(current.lock().unwrap().is_none());
        fake.await.unwrap();
    }

    #[tokio::test]
    async fn audit_missing_server_confirmation_releases_no_payload() {
        audit_untrusted_server_confirmation(0).await;
    }

    #[tokio::test]
    async fn audit_reflected_client_proof_releases_no_payload() {
        audit_untrusted_server_confirmation(1).await;
    }

    #[tokio::test]
    async fn audit_wrong_key_server_confirmation_releases_no_payload() {
        audit_untrusted_server_confirmation(2).await;
    }

    #[tokio::test]
    async fn audit_h3_control_stream_does_not_block_server_confirmation() {
        let (cert, k, pin) = test_cert();
        let endpoint = Endpoint::server(
            server_config(cert, k).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let key = [7; TOKEN_LEN];
        let task = tokio::spawn(async move {
            let c = endpoint.accept().await.unwrap().await.unwrap();
            let mut control = c.open_uni().await.unwrap();
            control.write_all(&[0, 4, 0]).await.unwrap(); // Deliberately never finish it.
            send_confirmation(&c, &key).await.unwrap();
            tokio::time::sleep(Duration::from_millis(500)).await;
            drop(control);
            endpoint.close(0u32.into(), b"test ended");
        });
        let (_client, c) = raw(addr, pin).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(400), confirm_server(&c, &key))
                .await
                .unwrap()
                .is_ok()
        );
        task.await.unwrap();
    }

    #[tokio::test]
    async fn audit_legacy_proof_never_authenticates() {
        let (_, _, pin) = test_cert();
        let (addr, wg, _) = server([7; TOKEN_LEN]).await;
        let (_client, c) = raw(addr, pin).await.unwrap();
        let mut old = c.open_uni().await.unwrap();
        old.write_all(&[0x40, 0x7e]).await.unwrap();
        old.write_all(&proof(&c, &[7; TOKEN_LEN]).unwrap())
            .await
            .unwrap();
        old.finish().unwrap();
        c.send_datagram(Bytes::from_static(b"old-peer-payload"))
            .unwrap();
        assert!(nothing_arrives(&wg).await);
    }
    async fn audit_untrusted_tcp_confirmation(mode: u8) {
        let (cert, k, pin) = test_cert();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(tls_server_config(cert, k).unwrap());
        let key = [7; TOKEN_LEN];
        let fake = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(socket).await.unwrap();
            let request = read_http_header(&mut tls).await.unwrap();
            let confirmation = if mode == 0 {
                String::new()
            } else if mode == 1 {
                let request = std::str::from_utf8(&request).unwrap();
                let reflected = request
                    .lines()
                    .find_map(|line| line.strip_prefix("If-None-Match: "))
                    .unwrap();
                format!("ETag: {reflected}\r\n")
            } else {
                format!(
                    "ETag: \"{}\"\r\n",
                    hex::encode(tls_server_proof(tls.get_ref().1, &[9; TOKEN_LEN]).unwrap())
                )
            };
            tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n{confirmation}\r\n").as_bytes()).await.unwrap();
            let mut byte = [0; 1];
            // Closing, TLS close errors and timeouts are acceptable; plaintext is not.
            let leaked =
                tokio::time::timeout(Duration::from_millis(600), tls.read(&mut byte)).await;
            if let Ok(Ok(n)) = leaked {
                assert_eq!(
                    n, 0,
                    "client released payload to an unauthenticated TCP server"
                );
            }
        });
        let connector = TlsConnector::from(tls_client_config(pin, true).unwrap());
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let current = Mutex::new(None);
        let held = Mutex::new(Held::default());
        held.lock()
            .unwrap()
            .push(Bytes::from_static(b"must-not-leak"));
        let stats = Stats::default();
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            tcp_session(
                &connector,
                None,
                addr,
                "cover.example",
                &key,
                &udp,
                udp.local_addr().unwrap(),
                &current,
                &held,
                &stats,
                Duration::from_secs(2),
            ),
        )
        .await
        .unwrap();
        assert!(result.is_err());
        assert!(!stats.connected.load(Ordering::Relaxed));
        assert_eq!(stats.sessions.load(Ordering::Relaxed), 0);
        assert!(current.lock().unwrap().is_none());
        fake.await.unwrap();
    }

    #[tokio::test]
    async fn audit_tcp_missing_confirmation_releases_no_payload() {
        audit_untrusted_tcp_confirmation(0).await;
    }

    #[tokio::test]
    async fn audit_tcp_reflected_confirmation_releases_no_payload() {
        audit_untrusted_tcp_confirmation(1).await;
    }

    #[tokio::test]
    async fn audit_tcp_wrong_key_confirmation_releases_no_payload() {
        audit_untrusted_tcp_confirmation(2).await;
    }

    #[tokio::test]
    async fn audit_server_confirmation_cannot_replay_across_tls_sessions() {
        let (cert, k, pin) = test_cert();
        let endpoint = Endpoint::server(
            server_config(cert, k).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let key = [7; TOKEN_LEN];
        let fake = tokio::spawn(async move {
            let first = endpoint.accept().await.unwrap().await.unwrap();
            let mut trigger = first.accept_uni().await.unwrap();
            trigger.read_to_end(1).await.unwrap();
            let captured = server_proof(&first, &key).unwrap();
            let second = endpoint.accept().await.unwrap().await.unwrap();
            let mut request = second.accept_uni().await.unwrap();
            request.read_to_end(64).await.unwrap();
            let mut confirmation = second.open_uni().await.unwrap();
            confirmation
                .write_all(&SERVER_CONFIRM_STREAM)
                .await
                .unwrap();
            confirmation.write_all(&captured).await.unwrap();
            confirmation.finish().unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(600), second.read_datagram())
                    .await
                    .is_err(),
                "replayed confirmation released payload"
            );
            endpoint.close(0u32.into(), b"test ended");
        });
        let (_first_endpoint, first) = raw(addr, pin).await.unwrap();
        let mut trigger = first.open_uni().await.unwrap();
        trigger.write_all(&[0]).await.unwrap();
        trigger.finish().unwrap();
        let (_second_endpoint, second) = raw(addr, pin).await.unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let current = Mutex::new(None);
        let held = Mutex::new(Held::default());
        held.lock()
            .unwrap()
            .push(Bytes::from_static(b"must-not-leak"));
        let stats = Stats::default();
        assert!(
            session(
                &second,
                &key,
                &udp,
                udp.local_addr().unwrap(),
                &current,
                &held,
                None,
                &stats,
            )
            .await
            .is_err()
        );
        assert!(!stats.connected.load(Ordering::Relaxed));
        assert!(current.lock().unwrap().is_none());
        fake.await.unwrap();
    }

    #[test]
    fn wire_clock_queue_cap_and_wake_interval_prevent_bufferbloat_and_relay5_skips() {
        // 4,000 pps fast class: 150 ms queue cap = 600 slots (vs 4,000 old 1 s bloat), floor 64.
        assert_eq!(wire_clock_queue_cap(4000.0), 600);
        assert_eq!(wire_clock_queue_cap(50.0), 64);
        // Adaptive wake interval: 5 ms lookahead wakes every 1.25 ms; 30 ms clamps to 2 ms; 1 ms clamps to 0.5 ms.
        assert_eq!(
            wire_clock_wake_interval(Duration::from_millis(5)),
            Duration::from_micros(1250)
        );
        assert_eq!(
            wire_clock_wake_interval(Duration::from_millis(30)),
            Duration::from_millis(2)
        );
        assert_eq!(
            wire_clock_wake_interval(Duration::from_millis(1)),
            Duration::from_micros(500)
        );
    }
}
