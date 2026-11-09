//! Real TLS handshakes: require hybrid KEX and mutual authentication, not just config strings.
use crate::{
    config::{Config, private_read},
    tls,
};
use quinn::{Endpoint, crypto::rustls::QuicClientConfig};
use std::{sync::Arc, time::Duration};

#[tokio::test]
async fn classical_only_and_anonymous_clients_cannot_negotiate() {
    let tmp = std::env::temp_dir().join(format!("avpn-crypto-{}", std::process::id()));
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
    let tmp = std::env::temp_dir().join(format!("avpn-auth-{}-{}", algorithm, std::process::id()));
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
    let ci: crate::config::Identity = serde_json::from_value(raw["outer"].clone()).unwrap();
    let si = server_cfg.outer.clone().unwrap();
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

#[test]
fn only_ml_dsa_65_is_verifiable() {
    let algorithms = tls::pq_signatures();
    assert_eq!(algorithms.mapping.len(), 1);
    assert_eq!(algorithms.mapping[0].0, tls::SIGNATURE_SCHEME);
}
