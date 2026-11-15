//! `avpn cloud`: create, inspect and remove the chain's cloud servers.
//!
//! The work is done by `avpn-cloud` (`tools/cloud.py`), which runs as you with your
//! own provider sign-in, never as root. For `--apply` and `--teardown`, this front
//! end first shows the plan (`--dry-run`), then asks for confirmation, then runs
//! the command with `--yes`.

use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::cells::{Cell, render};
use crate::controller::{Outcome, is_root};
use crate::progress::Checklist;
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

/// The marker before each structured progress event on the tool's stderr.
const EVENT: &str = "\u{1e}AVPN ";

enum Msg {
    Event(Value),
    Text(String),
}

/// Whether a PIN asked during the run will pop up as a desktop dialog (as the cloud
/// tool runs as you), or be typed on this terminal below the checklist.
fn desktop_dialog() -> bool {
    let var = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
    (var("WAYLAND_DISPLAY") || var("DISPLAY"))
        && !var("SSH_CONNECTION")
        && std::env::var("AVPN_PIN_DIALOG").as_deref() != Ok("0")
}

/// Run the cloud tool for a long operation and draw its steps as a live checklist
/// (`AVPN_PROGRESS=events`). The terminal stays the tool's for input (a PIN typed
/// here); its other stderr text is printed above the checklist; stdout still carries
/// the one JSON object.
fn call_live(args: &[String], theme: Theme, reduced_motion: bool) -> Outcome {
    let mut argv = vec!["--json".to_string()];
    argv.extend(args.iter().cloned());
    let child = Command::new(program())
        .args(&argv)
        .env("AVPN_PROGRESS", "events")
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            return Outcome {
                code: 1,
                value: serde_json::json!({"ok": false, "error": "NotInstalled"}),
                stderr: format!("cannot run {}: {e}", program().display()),
            };
        }
    };
    let mut stdout = child.stdout.take().expect("piped stdout");
    let reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stdout.read_to_string(&mut s);
        s
    });
    let (tx, rx) = mpsc::channel();
    let stderr = child.stderr.take().expect("piped stderr");
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let msg = match line
                .strip_prefix(EVENT)
                .and_then(|j| serde_json::from_str(j).ok())
            {
                Some(v) => Msg::Event(v),
                None => Msg::Text(line),
            };
            if tx.send(msg).is_err() {
                break;
            }
        }
    });

    let start = Instant::now();
    let mut list = Checklist::new(reduced_motion);
    let typed_here = !desktop_dialog();
    let mut drawn = 0usize;
    let mut out = std::io::stdout();
    // Redraw in place: up over what was drawn last, then each line over the old one.
    // `full` draws the whole list (once, at the end) instead of what fits the screen.
    let mut draw = |list: &Checklist, drawn: &mut usize, full: bool| {
        let (cols, rows) = terminal_size();
        let rows = if full { usize::MAX } else { rows };
        let lines = list.view(start, Instant::now(), theme, rows, cols);
        let mut s = String::new();
        if *drawn > 0 {
            s.push_str(&format!("\x1b[{}A", *drawn));
        }
        for line in &lines {
            s.push_str("\r\x1b[2K");
            s.push_str(&to_ansi(std::slice::from_ref(line), theme));
        }
        // Lines left over from a taller drawing (the terminal grew) are cleared.
        s.push_str("\x1b[J");
        let _ = out.write_all(s.as_bytes());
        let _ = out.flush();
        *drawn = lines.len();
    };
    loop {
        match rx.recv_timeout(Duration::from_millis(120)) {
            Ok(Msg::Event(v)) => {
                list.apply(&v, Instant::now());
                draw(&list, &mut drawn, false);
                if list.waiting() && typed_here {
                    // The PIN prompt prints below; continue with a fresh list after it.
                    drawn = 0;
                }
            }
            Ok(Msg::Text(t)) => {
                // Clear the list, print the text, draw the list again below it.
                let mut s = String::new();
                if drawn > 0 {
                    s.push_str(&format!("\x1b[{drawn}A"));
                    for _ in 0..drawn {
                        s.push_str("\r\x1b[2K\n");
                    }
                    s.push_str(&format!("\x1b[{drawn}A"));
                }
                s.push_str(&t);
                s.push('\n');
                let _ = std::io::stdout().write_all(s.as_bytes());
                drawn = 0;
                if list.height() > 0 {
                    draw(&list, &mut drawn, false);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if list.animating() {
                    draw(&list, &mut drawn, false);
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    if list.height() > 0 {
        draw(&list, &mut drawn, true);
    }
    let status = child.wait();
    let stdout = reader.join().unwrap_or_default();
    let value = stdout
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .and_then(|l| serde_json::from_str::<Value>(l).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| serde_json::json!({"ok": false, "error": "NoJsonFromController"}));
    Outcome {
        code: status.ok().and_then(|s| s.code()).unwrap_or(1),
        value,
        stderr: String::new(),
    }
}

/// Columns and rows of the terminal on stdout (80 x 24 when it cannot tell).
fn terminal_size() -> (usize, usize) {
    ratatui::crossterm::terminal::size()
        .ok()
        .filter(|&(c, r)| c > 0 && r > 0)
        .map_or((80, 24), |(c, r)| (usize::from(c), usize::from(r)))
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
pub fn main(args: &[String], json: bool, theme: Theme, reduced_motion: bool) -> i32 {
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
        // A chain apply runs for minutes: a live checklist of its steps on a terminal.
        let done = if std::io::stdout().is_terminal() {
            call_live(&go, theme, reduced_motion)
        } else {
            call(&go)
        };
        println!();
        show(&crate::cells::from_outcome("cloud", &done), theme);
        return if done.ok() { 0 } else { 1 };
    }
    let o = call(args);
    show(&crate::cells::from_outcome("cloud", &o), theme);
    if o.ok() { 0 } else { 1 }
}
