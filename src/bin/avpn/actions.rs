//! Actions shared by one-shot commands and the interactive view.

use std::process::Command;

use crate::cells::{Cell, Row, from_outcome};
use crate::controller::{Controller, SERVICE, systemctl};

/// The result of one action: an exit status and the cells to show.
pub struct Done {
    /// Exit status for one-shot use.
    pub code: i32,
    /// What to show.
    pub cells: Vec<Cell>,
}

fn failed(title: String, hints: Vec<String>) -> Done {
    Done {
        code: 1,
        cells: vec![Cell::Error { title, hints }],
    }
}

fn last_line(bytes: &[u8]) -> Option<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
}

/// Run `systemctl VERB advanced-vpn.service`.
fn service(verb: &str) -> Result<(), Vec<String>> {
    let program = systemctl().map_err(|e| vec![e.to_string()])?;
    let out = Command::new(program)
        .args([verb, SERVICE])
        .output()
        .map_err(|e| vec![e.to_string()])?;
    if out.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let mut hints = Vec::new();
        hints.extend(last_line(&out.stderr));
        hints.extend(service_hint(
            &stderr,
            crate::controller::is_root(),
            user_install(),
        ));
        Err(hints)
    }
}

/// What a device still needs before it can connect.
pub fn not_enrolled_steps(has_keys: bool) -> Vec<String> {
    let mut steps = Vec::new();
    if !has_keys {
        steps.push("1. generate its keys: sudo avpn request --role client --protect nitrokey --out client.req".into());
    }
    steps.push(
        "give the public request to the operator, who signs a chain with it (avpn init)".into(),
    );
    steps.push(
        "then: sudo avpn enroll client.avpn --operator-key operator.pub && sudo avpn connect"
            .into(),
    );
    steps
}

/// Whether this `avpn` is the per-user (operator) installation: it points at its own
/// controller instead of the system one in /opt/advanced-vpn.
fn user_install() -> bool {
    std::env::var_os("AVPN_CONTROLLER").is_some()
}

/// What to do when `systemctl` refuses: the right next step depends on whether the VPN
/// is installed at all, and on who is asking.
pub fn service_hint(stderr: &str, root: bool, user_install: bool) -> Vec<String> {
    let missing = stderr.contains("not found") || stderr.contains("not loaded");
    if stderr.contains("dependency job") {
        return vec![
            "the boot guard refused to start; usually this device is not enrolled yet".into(),
            "check: sudo avpn info  (and: sudo systemctl status advanced-vpn-guard.service)".into(),
        ];
    }
    if missing && user_install && !root {
        return vec![
            "this is the command-line-only install (install.py --user); it has no VPN service".into(),
            "to make this machine a VPN client: sudo python3 tools/install.py --apply --role client --protect nitrokey".into(),
        ];
    }
    if missing {
        return vec!["the VPN is not installed here: sudo python3 tools/install.py --apply --role client --protect nitrokey".into()];
    }
    if !root {
        return vec!["starting the service needs root: sudo avpn connect".into()];
    }
    vec!["see: systemctl status advanced-vpn.service".into()]
}

/// Run one controller action (or a service action) and turn it into cells.
pub fn perform(ctrl: &Controller, action: &str, args: &[String]) -> Done {
    match action {
        "connect" => {
            // Say "not enrolled" plainly instead of letting systemd report a failed guard.
            if let Ok(o) = ctrl.call("info", &[])
                && o.ok()
                && o.value["info"]["enrolled"] == serde_json::Value::Bool(false)
            {
                return failed(
                    "connect failed: this device is not enrolled yet".into(),
                    not_enrolled_steps(o.value["info"].get("role").is_some()),
                );
            }
            if let Err(h) = service("start") {
                return failed("connect failed".into(), h);
            }
            let mut cells = vec![Cell::Result {
                title: "Connected".into(),
                summary: Some(SERVICE.into()),
                rows: vec![Row::detail(
                    "started; a Nitrokey PIN, if needed, is asked for now (or: sudo avpn unlock)",
                )],
            }];
            cells.extend(status_cells(ctrl));
            Done { code: 0, cells }
        }
        "disconnect" => match service("stop") {
            Ok(()) => Done {
                code: 0,
                cells: vec![Cell::Result {
                    title: "Disconnected".into(),
                    summary: Some(SERVICE.into()),
                    rows: vec![Row::detail(
                        "stopped; the kill switch stays in place (avpn help reset)",
                    )],
                }],
            },
            // Not run by the service (e.g. `connect --foreground`): signal the supervisor.
            Err(_) => controller(ctrl, "disconnect", args),
        },
        _ => controller(ctrl, action, args),
    }
}

fn status_cells(ctrl: &Controller) -> Vec<Cell> {
    controller(ctrl, "status", &[]).cells
}

fn controller(ctrl: &Controller, action: &str, args: &[String]) -> Done {
    match ctrl.call(action, args) {
        Ok(o) => Done {
            code: if o.ok() { 0 } else { o.code.max(1) },
            cells: from_outcome(action, &o),
        },
        Err(e) => failed(
            format!("{action} failed"),
            vec![format!("{e:#}"), "avpn doctor".into()],
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::service_hint;

    #[test]
    fn hints_name_the_real_next_step() {
        let missing = "Failed to start advanced-vpn.service: Unit advanced-vpn.service not found.";
        let user = service_hint(missing, false, true).join("\n");
        assert!(user.contains("command-line-only install"), "{user}");
        assert!(user.contains("install.py --apply --role client"), "{user}");
        assert!(
            !user.contains("sudo avpn connect"),
            "sudo cannot help a user install: {user}"
        );
        assert!(service_hint(missing, true, false)[0].contains("not installed here"));
        assert_eq!(
            service_hint("Access denied", false, false),
            vec!["starting the service needs root: sudo avpn connect"]
        );
        assert!(service_hint("Job failed", true, false)[0].contains("systemctl status"));
        let dep =
            "A dependency job for advanced-vpn.service failed. See 'journalctl -xe' for details.";
        assert!(service_hint(dep, false, true)[0].contains("not enrolled"));
        assert!(
            super::not_enrolled_steps(true)
                .iter()
                .all(|s| !s.contains("avpn request"))
        );
        assert!(super::not_enrolled_steps(false)[0].contains("avpn request"));
    }
}
