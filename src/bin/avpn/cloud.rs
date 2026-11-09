//! `avpn cloud`: create, inspect and remove the chain's cloud servers.
//!
//! The work is done by `avpn-cloud` (`tools/cloud.py`), which runs as you with your
//! own provider sign-in, never as root. For `--apply` and `--teardown`, this front
//! end first shows the plan (`--dry-run`), then asks for confirmation, then runs
//! the command with `--yes`.

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

use crate::cells::{Cell, render};
use crate::controller::{Outcome, is_root};
use crate::theme::{Theme, to_ansi};

/// Where the installer puts the cloud launcher.
pub const DEFAULT_CLOUD: &str = "/opt/advanced-vpn/bin/avpn-cloud";

fn program() -> PathBuf {
    std::env::var_os("AVPN_CLOUD").map_or_else(|| PathBuf::from(DEFAULT_CLOUD), PathBuf::from)
}

/// Run the cloud tool with `--json` and parse its object.
pub fn call(args: &[String]) -> Outcome {
    let mut argv = vec!["--json".to_string()];
    argv.extend(args.iter().cloned());
    match Command::new(program()).args(&argv).output() {
        Ok(out) => {
            let value = String::from_utf8_lossy(&out.stdout)
                .lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .and_then(|l| serde_json::from_str::<Value>(l).ok())
                .filter(Value::is_object)
                .unwrap_or_else(
                    || serde_json::json!({"ok": false, "error": "NoJsonFromController"}),
                );
            Outcome {
                code: out.status.code().unwrap_or(1),
                value,
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            }
        }
        Err(e) => Outcome {
            code: 1,
            value: serde_json::json!({"ok": false, "error": "NotInstalled"}),
            stderr: format!("cannot run {}: {e}", program().display()),
        },
    }
}

fn show(cells: &[Cell], theme: Theme) {
    let _ = std::io::stdout()
        .lock()
        .write_all(to_ansi(&render(cells, theme), theme).as_bytes());
}

fn ask(question: &str) -> bool {
    if !std::io::stdin().is_terminal() {
        return false;
    }
    print!("{question} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    matches!(line.trim(), "y" | "Y" | "yes")
}

/// Entry point for `avpn cloud ARGS`.
pub fn main(args: &[String], json: bool, theme: Theme) -> i32 {
    if is_root() && std::env::var_os("AVPN_CLOUD").is_none() {
        show(
            &[Cell::Error {
                title: "run avpn cloud as yourself, not root".into(),
                hints: vec!["it uses your own aws / oci sign-in".into()],
            }],
            theme,
        );
        return 1;
    }
    if json {
        let o = call(args);
        println!("{}", o.value);
        return o.code;
    }
    let changes = args.iter().any(|a| a == "--apply" || a == "--teardown");
    let confirmed = args.iter().any(|a| a == "--yes" || a == "--dry-run");
    if changes && !confirmed {
        let mut plan_args = args.to_vec();
        plan_args.push("--dry-run".into());
        let plan = call(&plan_args);
        show(&crate::cells::from_outcome("cloud", &plan), theme);
        if !plan.ok() {
            return 1;
        }
        let nothing = plan.value["rows"]
            .as_array()
            .is_some_and(|r| r.len() == 1 && r[0]["label"] == "nothing");
        if nothing {
            return 0;
        }
        if !ask("Proceed?") {
            show(
                &[Cell::Error {
                    title: "cancelled".into(),
                    hints: vec!["nothing was changed".into()],
                }],
                theme,
            );
            return 1;
        }
        let mut go = args.to_vec();
        go.push("--yes".into());
        let done = call(&go);
        println!();
        show(&crate::cells::from_outcome("cloud", &done), theme);
        return if done.ok() { 0 } else { 1 };
    }
    let o = call(args);
    show(&crate::cells::from_outcome("cloud", &o), theme);
    if o.ok() { 0 } else { 1 }
}
