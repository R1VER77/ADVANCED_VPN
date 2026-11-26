//! `cypherpunk mesh`: browse the community mesh, offer nodes, build chains.
//!
//! The work is done by `cpvpn-mesh` (`tools/mesh.py`), which runs as you — with
//! your own cloud sign-ins and your own hardware token — never as root. For
//! changing operations (`offer --apply`, `chain --apply`, `publish`), this
//! front end first shows the plan (`--dry-run`), then asks for confirmation,
//! then runs the command with `--yes`. Same contract as `cypherpunk cloud`.

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

use crate::cells::{Cell, Row, render};
use crate::controller::{Outcome, is_root};
use crate::theme::{Theme, to_ansi};

/// Where the installer puts the mesh launcher.
pub const DEFAULT_MESH: &str = "/opt/cypherpunk-vpn/bin/cpvpn-mesh";

fn program() -> PathBuf {
    std::env::var_os("CPVPN_MESH").map_or_else(|| PathBuf::from(DEFAULT_MESH), PathBuf::from)
}

/// Run the mesh tool with `--json` and parse its object.
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

/// Render the credits or shared-access view through the same theme as the rest of the CLI.
pub fn credit_cells(outcome: &Outcome) -> Vec<Cell> {
    let value = &outcome.value;
    if outcome.ok() && value["shared_dashboard"] == true {
        let headline = value["shared_active_credits"]
            .as_u64()
            .zip(value["shared_pending_credits"].as_u64())
            .map(|(held, pending)| format!("{held} usable · {pending} pending · pilot disabled"))
            .or_else(|| {
                value["imported_credits"]
                    .as_u64()
                    .map(|n| format!("{n} sealed for next epoch"))
            });
        let rows = value["rows"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|row| Some(Row::pair(row["label"].as_str()?, row["value"].as_str()?)))
            .collect();
        return vec![Cell::Result {
            title: "Shared access".into(),
            summary: headline,
            rows,
        }];
    }
    if !outcome.ok() || value["credit_dashboard"] != true {
        return crate::cells::from_outcome("mesh", outcome);
    }
    let held = value["held_total"].as_u64().or_else(|| value["balance"].as_u64());
    let pending = value["pending_total"]
        .as_u64()
        .or_else(|| value["pending_next_epoch"].as_u64());
    let headline = held.zip(pending).map(|(h, p)| {
        let badge = value["pool_badge"]
            .as_str()
            .unwrap_or("Public pool disabled");
        format!("{h} held · {p} pending · {badge}")
    });
    let rows = value["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| {
            let label = row["label"].as_str()?;
            if headline.is_some() && matches!(label, "Held" | "Pending") {
                return None;
            }
            Some(Row::pair(label, row["value"].as_str()?))
        })
        .collect();
    vec![Cell::Result {
        title: "Mesh credits".into(),
        summary: headline,
        rows,
    }]
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

/// Entry point for `cypherpunk mesh ARGS`.
pub fn main(args: &[String], json: bool, theme: Theme) -> i32 {
    if is_root() && std::env::var_os("CPVPN_MESH").is_none() {
        show(
            &[Cell::Error {
                title: "run cypherpunk mesh as yourself, not root".into(),
                hints: vec!["it uses your own cloud sign-ins and your hardware token".into()],
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
    let changes = args.iter().any(|a| a == "--apply" || a == "--publish");
    let confirmed = args.iter().any(|a| a == "--yes" || a == "--dry-run");
    if changes && !confirmed {
        let mut plan_args = args.to_vec();
        plan_args.push("--dry-run".into());
        let plan = call(&plan_args);
        show(&crate::cells::from_outcome("mesh", &plan), theme);
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
        show(&crate::cells::from_outcome("mesh", &done), theme);
        return if done.ok() { 0 } else { 1 };
    }
    let o = call(args);
    show(&credit_cells(&o), theme);
    if o.ok() { 0 } else { 1 }
}
