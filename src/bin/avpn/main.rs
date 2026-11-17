//! `avpn`: the command-line front end of ADVANCED_VPN.
//!
//! With no command in a terminal, it opens the interactive view (see `avpn help
//! interactive`). With a command, it runs the privileged controller (`avpnctl`) with
//! `--json` and renders the result in the Codex transcript style. All validation
//! and all privileged work stay in the controller.
#![deny(missing_docs)]

mod actions;
mod app;
mod cells;
mod cloud;
mod controller;
mod mesh;
mod progress;
mod theme;
mod topics;

use std::io::{IsTerminal, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::controller::Controller;
use crate::theme::{Theme, to_ansi};

/// ADVANCED_VPN: a single-user, self-hosted, post-quantum VPN.
#[derive(Parser, Debug)]
#[command(
    name = "avpn",
    version,
    disable_help_subcommand = true,
    disable_help_flag = true
)]
struct Cli {
    /// Enrollment directory (default /etc/advanced-vpn/enrolled).
    #[arg(long, global = true)]
    state: Option<PathBuf>,
    /// Print the controller's JSON object instead of the rendered view.
    #[arg(long, global = true)]
    json: bool,
    /// No colour (also: NO_COLOR, or output that is not a terminal).
    #[arg(long, global = true)]
    no_color: bool,
    /// No spinner animation in the interactive view.
    #[arg(long, global = true)]
    reduced_motion: bool,
    /// Show the overview page.
    #[arg(short = 'h', long = "help")]
    help: bool,
    #[command(subcommand)]
    command: Option<Cmd>,
}

/// Everything after the command name, passed to the controller unchanged.
#[derive(Args, Debug, Default)]
struct Rest {
    /// Options for the command; see `avpn help COMMAND`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
    args: Vec<String>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Runtime status written by the supervisor.
    #[command(disable_help_flag = true)]
    Status(Rest),
    /// Non-secret summary of this device.
    #[command(disable_help_flag = true)]
    Info(Rest),
    /// The enrolled chain, hop by hop.
    #[command(disable_help_flag = true)]
    Hops(Rest),
    /// Self-checks; --check-egress shows the address your first hop sees.
    #[command(disable_help_flag = true)]
    Doctor(Rest),
    /// Check installation requirements without changing this system.
    #[command(disable_help_flag = true)]
    Preflight(Rest),
    /// Recheck resumable setup or review a confirmed hardware repair.
    #[command(disable_help_flag = true)]
    Setup(Rest),
    /// Start the VPN service (or --foreground).
    #[command(disable_help_flag = true)]
    Connect(Rest),
    /// Stop the VPN service; the kill switch stays.
    #[command(disable_help_flag = true)]
    Disconnect(Rest),
    /// Run one program inside the protected namespace.
    #[command(disable_help_flag = true)]
    Run(Rest),
    /// Generate this device's keys and a public request.
    #[command(disable_help_flag = true)]
    Request(Rest),
    /// Operator: sign a chain from the requests.
    #[command(disable_help_flag = true)]
    Init(Rest),
    /// Verify and install this device's bundle.
    #[command(disable_help_flag = true)]
    Enroll(Rest),
    /// Mode, daily cap and upstream entry.
    #[command(disable_help_flag = true)]
    Preferences(Rest),
    /// Rotate session certificates now.
    #[command(disable_help_flag = true)]
    Rotate(Rest),
    /// Re-apply the boot-time kill switch.
    #[command(disable_help_flag = true)]
    Guard(Rest),
    /// Answer the Nitrokey PIN prompt after boot.
    #[command(disable_help_flag = true)]
    Unlock(Rest),
    /// Remove the kill switch (--allow-cleartext).
    #[command(disable_help_flag = true)]
    Reset(Rest),
    /// Create, inspect and remove the chain's cloud servers.
    #[command(disable_help_flag = true)]
    Cloud(Rest),
    /// Browse the community mesh, offer nodes, build chains.
    #[command(disable_help_flag = true)]
    Mesh(Rest),
    /// The mix lane: a mixnet client inside the protected namespace.
    #[command(disable_help_flag = true)]
    Mix(Rest),
    /// Reference pages: avpn help [TOPIC].
    Help {
        /// A command or concept; omit for the list.
        topic: Option<String>,
    },
}

impl Cmd {
    fn split(self) -> (&'static str, Vec<String>) {
        match self {
            Cmd::Status(r) => ("status", r.args),
            Cmd::Info(r) => ("info", r.args),
            Cmd::Hops(r) => ("hops", r.args),
            Cmd::Doctor(r) => ("doctor", r.args),
            Cmd::Preflight(r) => ("preflight", r.args),
            Cmd::Setup(r) => ("setup", r.args),
            Cmd::Connect(r) => ("connect", r.args),
            Cmd::Disconnect(r) => ("disconnect", r.args),
            Cmd::Run(r) => ("run", r.args),
            Cmd::Request(r) => ("request", r.args),
            Cmd::Init(r) => ("init", r.args),
            Cmd::Enroll(r) => ("enroll", r.args),
            Cmd::Preferences(r) => ("preferences", r.args),
            Cmd::Rotate(r) => ("rotate", r.args),
            Cmd::Guard(r) => ("guard", r.args),
            Cmd::Unlock(r) => ("unlock", r.args),
            Cmd::Reset(r) => ("reset", r.args),
            Cmd::Cloud(r) => ("cloud", r.args),
            Cmd::Mesh(r) => ("mesh", r.args),
            Cmd::Mix(r) => ("mix", r.args),
            Cmd::Help { topic } => ("help", topic.into_iter().collect()),
        }
    }
}

fn print(lines: &[ratatui::text::Line<'_>], theme: Theme) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(to_ansi(lines, theme).as_bytes());
}

fn help(topic: Option<&str>, theme: Theme) -> i32 {
    match topic {
        None => {
            print(&topics::index(theme), theme);
            0
        }
        Some(name) => match topics::find(name) {
            Some(t) => {
                print(&topics::render(t.body, theme), theme);
                0
            }
            None => {
                print(
                    &cells::render(
                        &[cells::Cell::Error {
                            title: format!("no help topic `{name}`"),
                            hints: vec!["avpn help lists every topic".into()],
                        }],
                        theme,
                    ),
                    theme,
                );
                2
            }
        },
    }
}

/// Replace this process with the controller, for commands that own the terminal.
/// Whether `action` should run the controller directly on this terminal. Actions that
/// can unseal a Nitrokey vault ask for its PIN (and say when to touch the key) on the
/// terminal; run through the captured `--json` path they see no terminal, fall back to
/// the desktop dialog, and under sudo that dialog cannot open ("PIN dialog stopped").
fn takes_terminal(action: &str, json: bool, stdin_is_terminal: bool) -> bool {
    matches!(action, "request" | "init" | "enroll" | "setup") && !json && stdin_is_terminal
}

fn exec(ctrl: &Controller, action: &str, args: &[String]) -> i32 {
    let err = ctrl.command(false, action, args).exec();
    eprintln!("avpn: cannot run the controller: {err}");
    1
}

fn main() {
    let cli = Cli::parse();
    let theme = Theme::detect(cli.no_color);
    let code = run(cli, theme);
    std::process::exit(code);
}

fn run(cli: Cli, theme: Theme) -> i32 {
    if cli.help {
        return help(Some("overview"), theme);
    }
    let Some(command) = cli.command else {
        if std::io::stdout().is_terminal() && std::io::stdin().is_terminal() {
            let ctrl = match Controller::locate(cli.state) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("avpn: {e:#}");
                    return 1;
                }
            };
            return match app::run(ctrl, theme, cli.reduced_motion) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("avpn: {e:#}");
                    1
                }
            };
        }
        return help(Some("overview"), theme);
    };
    let (action, mut args) = command.split();
    if action == "help" {
        return help(args.first().map(String::as_str), theme);
    }
    if args.iter().any(|a| a == "-h" || a == "--help") {
        return help(Some(action), theme);
    }
    if action == "cloud" {
        return cloud::main(&args, cli.json, theme, cli.reduced_motion);
    }
    if action == "mesh" {
        return mesh::main(&args, cli.json, theme);
    }
    let ctrl = match Controller::locate(cli.state) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("avpn: {e:#}");
            return 1;
        }
    };
    match action {
        "run" | "unlock" | "mix" => return exec(&ctrl, action, &args),
        _ if takes_terminal(action, cli.json, std::io::stdin().is_terminal()) => {
            return exec(&ctrl, action, &args);
        }
        "connect" if args.iter().any(|a| a == "--foreground") => {
            args.retain(|a| a != "--foreground");
            return exec(&ctrl, "connect", &args);
        }
        _ => {}
    }
    if cli.json && !matches!(action, "connect" | "disconnect") {
        return match ctrl.command(true, action, &args).status() {
            Ok(s) => s.code().unwrap_or(1),
            Err(e) => {
                eprintln!("avpn: cannot run the controller: {e}");
                1
            }
        };
    }
    let done = actions::perform(&ctrl, action, &args);
    if cli.json {
        let ok = done.code == 0;
        println!("{}", serde_json::json!({"ok": ok, "action": action}));
    } else {
        print(&cells::render(&done.cells, theme), theme);
    }
    done.code
}

#[cfg(test)]
mod tests {
    use super::{Cli, takes_terminal};
    use clap::Parser;

    #[test]
    fn setup_and_preflight_forward_their_typed_options_to_the_controller() {
        for (argv, expected) in [
            (
                vec!["avpn", "--json", "preflight", "--hardware"],
                ("preflight", vec!["--hardware"]),
            ),
            (
                vec!["avpn", "setup", "--repair", "install_udev_rule"],
                ("setup", vec!["--repair", "install_udev_rule"]),
            ),
        ] {
            let parsed = Cli::try_parse_from(argv).expect("new command parses");
            let (name, args) = parsed.command.expect("command").split();
            assert_eq!(name, expected.0);
            assert_eq!(args, expected.1);
        }
    }

    #[test]
    fn pin_actions_get_the_terminal_only_when_typed_at_one() {
        // Live regression (14 Nov 2026): `sudo avpn enroll` ran the controller with no
        // terminal, so the Nitrokey PIN went to a desktop dialog that root cannot open.
        for action in ["request", "init", "enroll", "setup"] {
            assert!(takes_terminal(action, false, true), "{action}");
            assert!(
                !takes_terminal(action, true, true),
                "--json keeps one parseable object: {action}"
            );
            assert!(
                !takes_terminal(action, false, false),
                "no terminal to give: {action}"
            );
        }
        for action in ["status", "info", "doctor", "disconnect", "hops"] {
            assert!(!takes_terminal(action, false, true), "{action}");
        }
    }
}
