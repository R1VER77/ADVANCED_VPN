//! Real TLS handshakes: require hybrid KEX and mutual authentication, not just config strings.
use crate::{
    config::{Config, private_read},
    tls,
};
use quinn::{Endpoint, crypto::rustls::QuicClientConfig};
use std::{sync::Arc, time::Duration};

#[tokio::test]
async fn classical_only_and_anonymous_clients_cannot_negotiate() {
    let tmp = std::env::temp_dir().join(format!("cpvpn-crypto-{}", std::process::id()));
    let status = std::process::Command::new("python3")
        .args([
            "tools/provision.py",
            "--out",
            tmp.to_str().unwrap(),
            "--relay",
            "127.0.0.1:4433",
            "--exit",
            "127.0.0.1:4444",
        ])
        .status()
        .unwrap();
    assert!(status.success());
    {
        let server = Config::load(&tmp.join("relay/config.json")).unwrap();
        let si = server.outer.as_ref().unwrap();
        let raw: serde_json::Value =
            serde_json::from_slice(&private_read(&tmp.join("client/config.json"), 65536).unwrap())
                .unwrap();
        let ci: crate::config::Identity = serde_json::from_value(raw["outer"].clone()).unwrap();
        for classical in [true, false] {
            let server = Endpoint::server(
                tls::server(si, None, tls::OUTER_MTU).unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let addr = server.local_addr().unwrap();
            let task = tokio::spawn(async move {
                let incoming = server.accept().await.unwrap();
                let outcome = tokio::time::timeout(Duration::from_secs(3), incoming).await;
                assert!(matches!(outcome, Ok(Err(_))));
                server.close(0u32.into(), b"test done");
            });
            let mut provider = rustls::crypto::aws_lc_rs::default_provider();
            provider.kx_groups = if classical {
                vec![rustls::crypto::aws_lc_rs::kx_group::X25519]
            } else {
                vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768]
            };
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(rustls::pki_types::CertificateDer::from(
                    private_read(&ci.ca, 16384).unwrap(),
                ))
                .unwrap();
            let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots);
            let mut crypto = if classical {
                builder
                    .with_client_auth_cert(
                        vec![rustls::pki_types::CertificateDer::from(
                            private_read(&ci.cert, 16384).unwrap(),
                        )],
                        rustls::pki_types::PrivatePkcs8KeyDer::from(
                            private_read(&ci.key, 16384).unwrap(),
                        )
                        .into(),
                    )
                    .unwrap()
            } else {
                builder.with_no_client_auth()
            };
            crypto.alpn_protocols = vec![tls::ALPN.to_vec()];
            let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
                QuicClientConfig::try_from(crypto).unwrap(),
            )));
            let r = tokio::time::timeout(
                Duration::from_secs(3),
                endpoint.connect(addr, &ci.server_name).unwrap(),
            )
            .await;
            // TLS1.3 client may finish before learning that its absent certificate was rejected.
            if let Ok(Ok(c)) = r {
                assert!(
                    tokio::time::timeout(Duration::from_secs(3), c.closed())
                        .await
                        .is_ok()
                );
            }
            task.await.unwrap();
            endpoint.close(0u32.into(), b"test done");
        }
    };
    std::fs::remove_dir_all(tmp).unwrap();
}

/// Provision a fresh deployment and attempt a real mutual-TLS QUIC handshake
/// between the relay (server) and client outer identities, using this crate's
/// own server/client configuration.
async fn outer_handshake(algorithm: &str) -> bool {
    session_handshake(algorithm, None).await
}

/// `outer_handshake`, optionally with hardware-bound sessions (docs/HARDWARE_BOUND_SESSIONS.md):
/// the relay pins a client device key, and the client's leaf is rotated with a session
/// authorization by that key (`authorized`), by another key (`other`), or with none (`plain`).
async fn session_handshake(algorithm: &str, session: Option<&str>) -> bool {
    let tmp = std::env::temp_dir().join(format!(
        "cpvpn-auth-{}-{}-{}",
        algorithm,
        session.unwrap_or("none"),
        std::process::id()
    ));
    let status = std::process::Command::new("python3")
        .args([
            "tools/provision.py",
            "--out",
            tmp.to_str().unwrap(),
            "--relay",
            "127.0.0.1:4433",
            "--exit",
            "127.0.0.1:4444",
            "--algorithm",
            algorithm,
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let server_cfg = Config::load(&tmp.join("relay/config.json")).unwrap();
    let raw: serde_json::Value =
        serde_json::from_slice(&private_read(&tmp.join("client/config.json"), 65536).unwrap())
            .unwrap();
    let mut ci: crate::config::Identity = serde_json::from_value(raw["outer"].clone()).unwrap();
    let mut si = server_cfg.outer.clone().unwrap();
    if let Some(mode) = session {
        let leaf = tmp.join("client-session-leaf.der");
        let out = std::process::Command::new("python3")
            .args(["tools/session_auth_vectors.py", "leaf"])
            .arg(&ci.cert)
            .arg(&ci.key)
            .arg(&leaf)
            .arg(mode.strip_suffix("-no-device").unwrap_or(mode))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        // As `cypherpunk init` pins a managed client: its own identity certificate as the root,
        // its public key as the pin, and its device key.
        let pins: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        si.peer_device = Some(serde_json::from_value(pins["device"].clone()).unwrap());
        si.ca = pins["root"].as_str().unwrap().into();
        si.pin_kind = crate::config::PinKind::Spki;
        si.peer_sha256 = pins["spki_sha256"].as_str().unwrap().into();
        if mode == "session-no-device" {
            si.peer_device = None;
        }
        ci.cert = leaf;
        ci.key = pins["key"].as_str().unwrap().into();
    }
    // Classical material must already fail when the local configuration is built
    // (no ML-DSA signing key); otherwise the handshake itself must decide.
    let (Ok(server_tls), Ok(client_tls)) = (
        tls::server(&si, None, tls::OUTER_MTU),
        tls::client(&ci, None, tls::OUTER_MTU),
    ) else {
        std::fs::remove_dir_all(tmp).unwrap();
        return false;
    };
    let server = Endpoint::server(server_tls, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = server.local_addr().unwrap();
    let si2 = si.clone();
    let task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let ok = match tokio::time::timeout(Duration::from_secs(5), incoming).await {
            Ok(Ok(c)) => tls::authenticated(&c, &si2).is_ok(),
            _ => false,
        };
        server.close(0u32.into(), b"test done");
        ok
    });
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_tls);
    let client_ok = match tokio::time::timeout(
        Duration::from_secs(5),
        endpoint.connect(addr, &ci.server_name).unwrap(),
    )
    .await
    {
        Ok(Ok(c)) => tls::authenticated(&c, &ci).is_ok(),
        _ => false,
    };
    let server_ok = task.await.unwrap();
    endpoint.close(0u32.into(), b"test done");
    std::fs::remove_dir_all(tmp).unwrap();
    client_ok && server_ok
}

#[tokio::test]
async fn ml_dsa_identities_authenticate_and_classical_are_refused() {
    assert!(
        outer_handshake("ml-dsa-65").await,
        "ML-DSA-65 mutual authentication must succeed"
    );
    assert!(
        !outer_handshake("ecdsa").await,
        "a correctly pinned classical deployment must be refused"
    );
}

#[tokio::test]
async fn a_pinned_device_key_admits_only_the_sessions_it_authorized() {
    assert!(
        session_handshake("ml-dsa-65", Some("authorized")).await,
        "a session the pinned key authorized must connect"
    );
    assert!(
        !session_handshake("ml-dsa-65", Some("plain")).await,
        "a leaf without a session authorization must be refused"
    );
    assert!(
        !session_handshake("ml-dsa-65", Some("other")).await,
        "a session authorized by another key must be refused"
    );
}

/// Phase 2: the client presents a fresh session key certified by its pinned identity.
#[tokio::test]
async fn a_session_key_is_admitted_only_when_its_identity_and_device_both_vouch_for_it() {
    assert!(
        session_handshake("ml-dsa-65", Some("session")).await,
        "a session key certified by the identity and named by the device must connect"
    );
    assert!(
        !session_handshake("ml-dsa-65", Some("session-no-device")).await,
        "without a pinned device key, only the identity key itself is accepted"
    );
    assert!(
        !session_handshake("ml-dsa-65", Some("session-other-identity")).await,
        "a session key certified by another ML-DSA-65 key must be refused"
    );
    assert!(
        !session_handshake("ml-dsa-65", Some("session-names-identity")).await,
        "the device's statement must name the session key itself"
    );
    assert!(
        !session_handshake("ml-dsa-65", Some("session-extra-root")).await,
        "a session key certified by another trusted identity is not the pinned peer's"
    );
}

#[test]
fn only_ml_dsa_65_is_verifiable() {
    let algorithms = tls::pq_signatures();
    assert_eq!(algorithms.mapping.len(), 1);
    assert_eq!(algorithms.mapping[0].0, tls::SIGNATURE_SCHEME);
}

/// The server name and ALPN offers of one ClientHello.
type Hello = (Option<String>, Vec<Vec<u8>>);

/// Records every ClientHello it sees, then refuses.
#[derive(Debug, Default)]
struct HelloRecorder(std::sync::Mutex<Vec<Hello>>);

impl rustls::server::ResolvesServerCert for HelloRecorder {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let alpn = hello
            .alpn()
            .map(|a| a.map(<[u8]>::to_vec).collect())
            .unwrap_or_default();
        self.0
            .lock()
            .unwrap()
            .push((hello.server_name().map(str::to_owned), alpn));
        None
    }
}

#[tokio::test]
async fn client_hello_names_neither_the_server_nor_this_tool() {
    let tmp = std::env::temp_dir().join(format!("cpvpn-hello-{}", std::process::id()));
    let status = std::process::Command::new("python3")
        .args([
            "tools/provision.py",
            "--out",
            tmp.to_str().unwrap(),
            "--relay",
            "127.0.0.1:4433",
            "--exit",
            "127.0.0.1:4444",
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let raw: serde_json::Value =
        serde_json::from_slice(&private_read(&tmp.join("client/config.json"), 65536).unwrap())
            .unwrap();
    let ci: crate::config::Identity = serde_json::from_value(raw["outer"].clone()).unwrap();
    let recorder = Arc::new(HelloRecorder::default());
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_cert_resolver(recorder.clone());
    server.alpn_protocols = vec![tls::ALPN.to_vec()];
    let server = Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server).unwrap(),
        )),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(3), incoming).await;
        server.close(0u32.into(), b"test done");
    });
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(tls::client(&ci, None, tls::OUTER_MTU).unwrap());
    // The handshake fails (the recorder offers no certificate); only the ClientHello matters.
    let _ = tokio::time::timeout(
        Duration::from_secs(3),
        endpoint.connect(addr, &ci.server_name).unwrap(),
    )
    .await;
    task.await.unwrap();
    endpoint.close(0u32.into(), b"test done");
    let seen = recorder.0.lock().unwrap().clone();
    assert!(
        ci.server_name.contains("cypherpunk-vpn"),
        "the test must use a revealing name"
    );
    assert_eq!(seen, vec![(None, vec![b"h3".to_vec()])]);
    std::fs::remove_dir_all(tmp).unwrap();
}
