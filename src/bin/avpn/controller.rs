//! The privileged engine: `avpnctl`, the Python controller.
//!
//! `avpn` never re-implements privileged logic. It runs the controller with `--json`,
//! reads the single JSON object it prints, and renders it.

use std::ffi::OsString;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde_json::Value;

/// Where the installer puts the controller launcher.
pub const DEFAULT_CONTROLLER: &str = "/opt/advanced-vpn/bin/avpnctl";
/// The only `systemctl` the CLI runs.
pub const SYSTEMCTL: &str = "/usr/bin/systemctl";
/// The client service that `avpn connect` and `avpn disconnect` drive.
pub const SERVICE: &str = "advanced-vpn.service";

/// True when this process runs as root.
pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions, cannot fail and touches no memory.
    unsafe { libc::geteuid() == 0 }
}

/// An executable is trusted for root use when it is a regular file owned by root
/// and not writable by group or others (the same rule as the controller's).
pub fn trusted_for_root(path: &Path) -> Result<()> {
    let m = std::fs::metadata(path).with_context(|| format!("{} is missing", path.display()))?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        bail!(
            "{} is not a root-owned, write-protected file",
            path.display()
        );
    }
    Ok(())
}

/// Resolve an executable that tests and development may override through an
/// environment variable. Root never honours the override: `sudo -E` must not be a
/// way to run someone else's program as root.
fn overridable(var: &str, default: &str) -> Result<PathBuf> {
    if !is_root()
        && let Some(path) = std::env::var_os(var)
    {
        return Ok(PathBuf::from(path));
    }
    let path = PathBuf::from(default);
    if is_root() {
        trusted_for_root(&path)?;
    }
    Ok(path)
}

/// The `systemctl` to run (`AVPN_SYSTEMCTL` overrides it for unprivileged tests).
pub fn systemctl() -> Result<PathBuf> {
    overridable("AVPN_SYSTEMCTL", SYSTEMCTL)
}

/// What one controller invocation produced.
#[derive(Clone, Debug)]
pub struct Outcome {
    /// The controller's exit status.
    pub code: i32,
    /// The JSON object it printed (an `ok: false` object when it printed none).
    pub value: Value,
    /// Its standard error, which holds the human-readable failure line.
    pub stderr: String,
}

impl Outcome {
    /// Whether the controller reported success.
    pub fn ok(&self) -> bool {
        self.code == 0 && self.value.get("ok").and_then(Value::as_bool) == Some(true)
    }
}

/// A located controller, plus the global options passed to every call.
#[derive(Clone, Debug)]
pub struct Controller {
    program: PathBuf,
    state: Option<PathBuf>,
}

impl Controller {
    /// Find the controller (`AVPN_CONTROLLER` overrides it for unprivileged use).
    pub fn locate(state: Option<PathBuf>) -> Result<Self> {
        Ok(Self {
            program: overridable("AVPN_CONTROLLER", DEFAULT_CONTROLLER)?,
            state,
        })
    }

    /// The controller command line for `action` and `args`, with `--json` when asked.
    pub fn command(&self, json: bool, action: &str, args: &[String]) -> Command {
        let mut c = Command::new(&self.program);
        let mut argv: Vec<OsString> = Vec::new();
        if json {
            argv.push("--json".into());
        }
        if let Some(state) = &self.state {
            argv.push("--state".into());
            argv.push(state.into());
        }
        argv.push(action.into());
        argv.extend(args.iter().map(OsString::from));
        c.args(argv);
        c
    }

    /// Run `action` with `--json` and parse the one object it prints.
    pub fn call(&self, action: &str, args: &[String]) -> Result<Outcome> {
        let out = self
            .command(true, action, args)
            .output()
            .with_context(|| format!("cannot run the controller {}", self.program.display()))?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        let value = stdout
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .and_then(|l| serde_json::from_str::<Value>(l).ok())
            .filter(Value::is_object)
            .unwrap_or_else(|| serde_json::json!({"ok": false, "error": "NoJsonFromController"}));
        Ok(Outcome {
            code: out.status.code().unwrap_or(1),
            value,
            stderr,
        })
    }
}
