//! The `cypherpunk` binary end to end, with stub controller, cloud tool and systemctl.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Stubs {
    dir: PathBuf,
}

impl Stubs {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("cpvpn-cli-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let s = Self { dir };
        // The controller stub logs its argv and answers like cypherpunkctl --json.
        s.script(
            "cypherpunkctl",
            r#"echo "$@" >> "$STUB/ctl.log"
for a in "$@"; do last="$a"; done
case "$*" in
  *--json*hops*) echo '{"ok": true, "action": "hops", "hops": 1, "chain": [{"hop": "exit", "endpoint": "16.0.0.9:51820"}]}' ;;
  *--json*status*) echo '{"ok": true, "action": "status", "status": {"state": "supervising", "kill_switch": true, "children": {"carrier": {"pid": 7, "alive": true}}}}' ;;
  *--json*disconnect*) echo '{"ok": true, "action": "disconnect", "message": "Disconnect requested; the kill switch stays in place."}' ;;
  *--json*preferences*) echo '{"ok": false, "error": "RuntimeError", "message": "managed networking requires the installed root supervisor"}'; echo 'Managed operation stopped: RuntimeError (managed networking requires the installed root supervisor).' >&2; exit 1 ;;
  *) echo '{"ok": true, "action": "x", "message": "done"}' ;;
esac"#,
        );
        s.script("systemctl", r#"echo "$@" >> "$STUB/systemctl.log"; [ -e "$STUB/systemctl.fail" ] && { echo "Unit cypherpunk-vpn.service not loaded." >&2; exit 5; }; exit 0"#);
        s.script(
            "cpvpn-cloud",
            r#"echo "$@" >> "$STUB/cloud.log"
case "$*" in
  *--dry-run*) echo '{"ok": true, "action": "cloud", "title": "Create AWS relay cpvpn-relay", "summary": "plan", "dry_run": true, "rows": [{"label": "instance", "value": "t3.micro cpvpn-relay"}]}' ;;
  *--yes*) echo '{"ok": true, "action": "cloud", "title": "Create AWS relay cpvpn-relay", "summary": "created", "rows": [{"label": "instance", "value": "i-1"}]}' ;;
  *) echo '{"ok": true, "action": "cloud", "title": "Cloud", "summary": "inventory", "rows": [{"label": "cpvpn-relay", "value": "aws relay"}]}' ;;
esac"#,
        );
        s
    }

    fn script(&self, name: &str, body: &str) {
        let p = self.dir.join(name);
        fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn cpvpn(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_cypherpunk"))
            .args(args)
            .env("CPVPN_CONTROLLER", self.dir.join("cypherpunkctl"))
            .env("CPVPN_SYSTEMCTL", self.dir.join("systemctl"))
            .env("CPVPN_CLOUD", self.dir.join("cpvpn-cloud"))
            .env("STUB", &self.dir)
            .env_remove("NO_COLOR")
            .output()
            .unwrap()
    }

    fn log(&self, name: &str) -> String {
        fs::read_to_string(self.dir.join(name)).unwrap_or_default()
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

impl Drop for Stubs {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn text(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn piped_output_is_plain_codex_cells() {
    let s = Stubs::new("plain");
    let o = s.cpvpn(&["hops"]);
    assert!(o.status.success());
    assert_eq!(
        text(&o),
        "• Chain  1-hop\n  └ client → exit 16.0.0.9:51820\n"
    );
    assert!(
        s.log("ctl.log").starts_with("--json hops"),
        "{}",
        s.log("ctl.log")
    );
}

#[test]
fn json_passes_the_controller_object_through() {
    let s = Stubs::new("json");
    let o = s.cpvpn(&["--json", "--state", "/tmp/x", "hops"]);
    let v: serde_json::Value = serde_json::from_str(text(&o).trim()).unwrap();
    assert_eq!(v["chain"][0]["hop"], "exit");
    assert_eq!(s.log("ctl.log").trim(), "--json --state /tmp/x hops");
}

#[test]
fn failures_exit_nonzero_with_the_reason() {
    let s = Stubs::new("fail");
    let o = s.cpvpn(&["preferences", "--defense", "strong"]);
    assert_eq!(o.status.code(), Some(1));
    let t = text(&o);
    assert!(t.starts_with("■ preferences failed: RuntimeError\n"), "{t}");
    assert!(t.contains("root supervisor"), "{t}");
    assert!(t.contains("cypherpunk help preferences"), "{t}");
    assert_eq!(
        s.log("ctl.log").trim(),
        "--json preferences --defense strong"
    );
}

#[test]
fn connect_on_an_unenrolled_device_says_so_and_never_starts_the_unit() {
    let s = Stubs::new("unenrolled");
    s.script(
        "cypherpunkctl",
        r#"echo "$@" >> "$STUB/ctl.log"; echo '{"ok": true, "action": "info", "info": {"enrolled": false, "state": "/etc/cypherpunk-vpn/enrolled", "status": {"state": "not running"}}}'"#,
    );
    let o = s.cpvpn(&["connect"]);
    assert_eq!(o.status.code(), Some(1));
    let t = text(&o);
    assert!(
        t.starts_with("■ connect failed: this device is not enrolled yet"),
        "{t}"
    );
    assert!(t.contains("sudo cypherpunk request --role client"), "{t}");
    assert_eq!(s.log("systemctl.log"), "", "systemctl must not run");
}

#[test]
fn connect_starts_the_unit_then_shows_status() {
    let s = Stubs::new("connect");
    let o = s.cpvpn(&["connect"]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(
        s.log("systemctl.log").trim(),
        "start cypherpunk-vpn.service"
    );
    let t = text(&o);
    assert!(
        t.contains("• VPN service started  cypherpunk-vpn.service"),
        "{t}"
    );
    assert!(t.contains("sudo cypherpunk unlock"), "{t}");
    assert!(t.contains("• Status  supervising"), "{t}");
    assert!(t.contains("  ✓ carrier  pid 7"), "{t}");
}

#[test]
fn disconnect_checks_the_foreground_supervisor_even_after_stopping_the_unit() {
    let s = Stubs::new("disconnect");
    assert!(s.cpvpn(&["disconnect"]).status.success());
    assert_eq!(s.log("systemctl.log").trim(), "stop cypherpunk-vpn.service");
    assert_eq!(s.log("ctl.log"), "--json disconnect\n");
    fs::write(s.path("systemctl.fail"), "").unwrap();
    let o = s.cpvpn(&["disconnect"]);
    assert!(o.status.success());
    assert_eq!(s.log("ctl.log"), "--json disconnect\n--json disconnect\n");
}

#[test]
fn help_pages_are_built_in_and_unknown_topics_fail() {
    let s = Stubs::new("help");
    let o = s.cpvpn(&["help", "privacy"]);
    assert!(o.status.success());
    assert!(text(&o).starts_with("Privacy and your source address\n"));
    assert!(s.cpvpn(&["enroll", "--help"]).status.success());
    assert!(text(&s.cpvpn(&["enroll", "--help"])).contains("--replace"));
    assert_eq!(s.cpvpn(&["help", "nope"]).status.code(), Some(2));
    assert_eq!(s.log("ctl.log"), "", "help never runs the controller");
}

#[test]
fn cloud_changes_show_a_plan_and_need_confirmation() {
    let s = Stubs::new("cloud");
    // No terminal to answer on: the plan is shown and nothing is applied.
    let o = s.cpvpn(&["cloud", "aws", "relay", "--apply", "--allow-from", "auto"]);
    assert_eq!(o.status.code(), Some(1));
    let t = text(&o);
    assert!(t.contains("• Create AWS relay cpvpn-relay  plan"), "{t}");
    assert!(t.contains("■ cancelled"), "{t}");
    assert_eq!(
        s.log("cloud.log").trim(),
        "--json aws relay --apply --allow-from auto --dry-run"
    );
    // --yes goes straight through.
    let o = s.cpvpn(&[
        "cloud",
        "aws",
        "relay",
        "--apply",
        "--allow-from",
        "auto",
        "--yes",
    ]);
    assert!(o.status.success());
    assert!(text(&o).contains("created"));
}

#[test]
fn no_escape_sequences_when_not_a_terminal_even_with_colour_allowed() {
    let s = Stubs::new("ansi");
    for args in [&["status"][..], &["help", "overview"], &["cloud", "status"]] {
        let o = s.cpvpn(args);
        assert!(!text(&o).contains('\x1b'), "{args:?}");
    }
    assert!(Path::new(env!("CARGO_BIN_EXE_cypherpunk")).exists());
}
