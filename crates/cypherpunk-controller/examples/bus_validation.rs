//! Disposable-VM integration client. Never part of the privileged daemon or GUI.
//! The positive fixture grants test-user Polkit rights only inside that VM; it
//! does not qualify an actual native authentication agent or hardware prompt.

use std::{fs, os::unix::fs::MetadataExt, time::Duration};
use zbus::{Connection, Proxy};

const NAME: &str = "org.cypherpunk_vpn.Controller1";
const OBJECT: &str = "/org/cypherpunk_vpn/Controller1";

async fn connect() -> Result<Connection, Box<dyn std::error::Error>> {
    Ok(
        zbus::connection::Builder::address("unix:path=/run/dbus/system_bus_socket")
            .method_timeout(Duration::from_secs(30))
            .build()
            .await?,
    )
}

fn parsed(raw: String) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let value: serde_json::Value = serde_json::from_str(&raw)?;
    assert_eq!(value["schema"], 1);
    Ok(value)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // SAFETY: geteuid has no arguments or memory preconditions.
    let uid = unsafe { libc::geteuid() };
    assert_ne!(uid, 0, "run as a disposable ordinary test user");
    let fixture = "/run/cypherpunk-controller-validation.fixture";
    let meta = fs::symlink_metadata(fixture)?;
    assert!(meta.is_file() && meta.uid() == 0 && meta.mode() & 0o022 == 0 && meta.len() == 30);
    assert_eq!(fs::read(fixture)?, b"disposable-controller-test-v1\n");
    let denied = std::env::args().nth(1).as_deref() == Some("denied");
    let first = connect().await?;
    assert!(
        first.request_name(NAME).await.is_err(),
        "unprivileged service-name takeover"
    );
    let proxy = Proxy::new(&first, NAME, OBJECT, NAME).await?;
    let snapshot: Result<String, _> = proxy.call("GetSnapshot", &()).await;
    if denied {
        assert!(
            snapshot.is_err(),
            "inactive user obtained unapproved observation"
        );
        println!("{{\"schema\":1,\"status\":\"denied_as_expected\"}}");
        return Ok(());
    }
    let snapshot = parsed(snapshot?)?;
    assert_ne!(
        snapshot["protection"], "protected",
        "unenrolled VM manufactured protection"
    );
    let private: Result<String, _> = proxy.call("GetPlan", &("a".repeat(64),)).await;
    assert!(
        private.is_err(),
        "private worker lookup exported on system bus"
    );
    let setup = parsed(proxy.call("GetSetup", &("join",)).await?)?;
    assert_eq!(setup["branch"], "join");
    assert_eq!(setup["finished"], false);
    for raw in [
        r#"{"action":"disconnect","caller":{"uid":0}}"#.to_owned(),
        r#"{"action":"disconnect","pin":"never-send-a-pin"}"#.to_owned(),
        "x".repeat(1_500_001),
    ] {
        let bad: Result<String, _> = proxy.call("PreviewAction", &(raw,)).await;
        assert!(
            bad.is_err(),
            "malformed or oversized public request accepted"
        );
    }
    let plan = parsed(
        proxy
            .call("PreviewAction", &(r#"{"action":"disconnect"}"#,))
            .await?,
    )?;
    let token = plan["id"].as_str().ok_or("missing plan ID")?;
    let second = connect().await?;
    assert_ne!(first.unique_name(), second.unique_name());
    let other = Proxy::new(&second, NAME, OBJECT, NAME).await?;
    let stolen: Result<String, _> = other.call("ApplyAction", &(token,)).await;
    assert!(
        stolen.is_err(),
        "same-UID different connection stole the plan"
    );
    let operation = parsed(proxy.call("ApplyAction", &(token,)).await?)?;
    let id = operation["id"].as_str().ok_or("missing operation ID")?;
    let stolen: Result<String, _> = other.call("CancelOperation", &(id,)).await;
    assert!(
        stolen.is_err(),
        "different connection cancelled an owned operation"
    );
    let replay: Result<String, _> = proxy.call("ApplyAction", &(token,)).await;
    assert!(replay.is_err(), "consumed plan replay accepted");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let result = parsed(proxy.call("GetOperation", &(id,)).await?)?;
        if result["state"] == "complete" {
            break;
        }
        assert_ne!(
            result["state"], "failed",
            "reviewed inert disconnect failed"
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "operation did not finish"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // All refusals above retained the original caller; progress remains readable.
    println!("{{\"schema\":1,\"status\":\"passed_bus_boundary_with_test_authorization\"}}");
    Ok(())
}
