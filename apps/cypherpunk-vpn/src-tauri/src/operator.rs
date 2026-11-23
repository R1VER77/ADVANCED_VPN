//! The own-servers side of setup: the installed `cpvpn-desktop` helper, run as this user.
//!
//! The WebView names only a provider key, server names, a number of hours and the
//! device's public request; each is checked here and again by the helper. The helper
//! path and every argument shape are fixed: no shell, no caller-chosen program or file.
//! Cloud sign-ins and the operator's vault stay with the helper; device keys stay with
//! the root controller.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

const HELPER: &str = "/opt/cypherpunk-vpn/bin/cpvpn-desktop";
const RESPONSE_LIMIT: usize = 256 * 1024;
const REQUEST_LIMIT: usize = 64 * 1024;
const EVENT_LIMIT: usize = 400;
const HOURS: [u8; 7] = [2, 4, 6, 8, 12, 16, 24];

pub fn provider_key(value: &str) -> Result<(), String> {
    let ok = (1..=16).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    if ok {
        Ok(())
    } else {
        Err("invalid_provider".into())
    }
}

/// The agreement's version: the SHA-256 of its documents, as 64 lowercase hex digits.
pub fn agreement_version(value: &str) -> Result<(), String> {
    let ok = value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok {
        Ok(())
    } else {
        Err("invalid_agreement_version".into())
    }
}

pub fn server_name(value: &str) -> Result<(), String> {
    let rest = value.strip_prefix("cpvpn-").unwrap_or("");
    let ok = (1..=40).contains(&rest.len())
        && rest
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok {
        Ok(())
    } else {
        Err("invalid_server".into())
    }
}

/// The helper's arguments for a chain build, after every check.
pub fn build_arguments(order: &[String], hours: u8) -> Result<Vec<String>, String> {
    if order.is_empty() || order.len() > 3 {
        return Err("one_to_three_servers".into());
    }
    for (i, name) in order.iter().enumerate() {
        server_name(name)?;
        if order[..i].contains(name) {
            return Err("one_to_three_servers".into());
        }
    }
    if !HOURS.contains(&hours) {
        return Err("invalid_hours".into());
    }
    Ok(vec![
        "build".into(),
        "--order".into(),
        order.join(","),
        "--hours".into(),
        hours.to_string(),
    ])
}

fn checked_json(raw: &[u8]) -> Result<String, String> {
    if raw.len() > RESPONSE_LIMIT {
        return Err("helper_response_too_large".into());
    }
    let text = std::str::from_utf8(raw).map_err(|_| "invalid_helper_response")?;
    let value: serde_json::Value =
        serde_json::from_str(text.trim()).map_err(|_| "invalid_helper_response")?;
    if value.get("schema").and_then(|x| x.as_u64()) != Some(1) {
        return Err("invalid_helper_schema".into());
    }
    Ok(text.trim().to_string())
}

/// One short helper call (state, check, add, remove).
pub fn call(args: &[&str]) -> Result<String, String> {
    let output = Command::new(HELPER)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| "helper_unavailable")?;
    checked_json(&output.stdout)
}

/// Save the device's public request to a file (the join path), through the helper.
pub fn export(request: &str) -> Result<String, String> {
    if request.is_empty() || request.len() > REQUEST_LIMIT {
        return Err("invalid_device_request".into());
    }
    let mut child = Command::new(HELPER)
        .arg("export")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "helper_unavailable")?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(request.as_bytes());
    }
    let output = child.wait_with_output().map_err(|_| "helper_unavailable")?;
    checked_json(&output.stdout)
}

#[derive(Default)]
pub struct Build {
    running: bool,
    events: Vec<String>,
}

#[derive(Default, Clone)]
pub struct Builds(pub Arc<Mutex<Build>>);

impl Builds {
    pub fn start(&self, order: Vec<String>, hours: u8, request: String) -> Result<(), String> {
        let args = build_arguments(&order, hours)?;
        if request.is_empty() || request.len() > REQUEST_LIMIT {
            return Err("invalid_device_request".into());
        }
        {
            let mut build = self.0.lock().map_err(|_| "build_state_unavailable")?;
            if build.running {
                return Err("build_already_running".into());
            }
            build.running = true;
            build.events.clear();
        }
        let mut child = match Command::new(HELPER)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(_) => {
                self.finish(r#"{"schema":1,"event":"error","error":"helper_unavailable"}"#.into());
                return Err("helper_unavailable".into());
            }
        };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(request.as_bytes());
        }
        let stdout = child.stdout.take();
        let state = self.clone();
        std::thread::spawn(move || {
            if let Some(stdout) = stdout {
                for line in BufReader::new(stdout).split(b'\n') {
                    let Ok(line) = line else { break };
                    match checked_json(&line) {
                        Ok(event) => state.push(event),
                        Err(_) => continue,
                    }
                }
            }
            let _ = child.wait();
            state.finish(String::new());
        });
        Ok(())
    }

    fn push(&self, event: String) {
        if let Ok(mut build) = self.0.lock() {
            if build.events.len() >= EVENT_LIMIT {
                build.events.remove(0);
            }
            build.events.push(event);
        }
    }

    fn finish(&self, event: String) {
        if !event.is_empty() {
            self.push(event);
        }
        if let Ok(mut build) = self.0.lock() {
            build.running = false;
        }
    }

    /// `{"schema":1,"running":bool,"events":[...]}`: the helper's own JSON events, in order.
    pub fn status(&self) -> Result<String, String> {
        let build = self.0.lock().map_err(|_| "build_state_unavailable")?;
        let events: Vec<serde_json::Value> = build
            .events
            .iter()
            .filter_map(|e| serde_json::from_str(e).ok())
            .collect();
        Ok(
            serde_json::json!({"schema": 1, "running": build.running, "events": events})
                .to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agreement_versions_are_sha256_hex() {
        assert!(agreement_version(&"0a".repeat(32)).is_ok());
        for bad in [
            String::new(),
            "0a".repeat(31),
            "0a".repeat(33),
            "0A".repeat(32),
            format!("{}--x", "0".repeat(61)),
            format!("{}\n", "0".repeat(63)),
        ] {
            assert!(agreement_version(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn provider_keys_are_plain_lowercase_words() {
        for good in ["aws", "oci", "1984", "digitalocean"] {
            assert!(provider_key(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "AWS",
            "../x",
            "a;b",
            "a b",
            "abcdefghijklmnopq",
            "--help",
        ] {
            assert!(provider_key(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_build_takes_recorded_style_names_and_fixed_hours_only() {
        let order = vec!["cpvpn-relay".to_string(), "cpvpn-flyexit".to_string()];
        assert_eq!(
            build_arguments(&order, 6).unwrap(),
            [
                "build",
                "--order",
                "cpvpn-relay,cpvpn-flyexit",
                "--hours",
                "6"
            ]
        );
        assert!(build_arguments(&order, 7).is_err());
        assert!(build_arguments(&[], 8).is_err());
        let dup = vec!["cpvpn-relay".to_string(), "cpvpn-relay".to_string()];
        assert!(build_arguments(&dup, 8).is_err());
        for bad in [
            "--accept-cost",
            "cpvpn-",
            "relay",
            "cpvpn-a,cpvpn-b",
            "cpvpn-A",
            "cpvpn-x/../y",
        ] {
            assert!(build_arguments(&[bad.to_string()], 8).is_err(), "{bad}");
        }
        let four: Vec<String> = (0..4).map(|i| format!("cpvpn-s{i}")).collect();
        assert!(build_arguments(&four, 8).is_err());
    }

    #[test]
    fn helper_replies_must_be_bounded_schema_one_json() {
        assert!(checked_json(br#"{"schema":1,"x":2}"#).is_ok());
        assert!(checked_json(br#"{"schema":2}"#).is_err());
        assert!(checked_json(b"not json").is_err());
        assert!(checked_json(&vec![b' '; RESPONSE_LIMIT + 1]).is_err());
    }
}
