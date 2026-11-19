//! Only the system bus supplies caller identity; only Polkit supplies authority.
//! The Python worker accepts inherited private pipes, never public IPC or a path
//! selected by a WebView. All public failures use fixed, secret-free messages.

use std::{collections::HashMap, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::Mutex,
};
use zbus::{Connection, Proxy, Variant, fdo, message::Header};

const NAME: &str = "org.cypherpunk_vpn.Controller1";
const OBJECT: &str = "/org/cypherpunk_vpn/Controller1";
const MAX_REQUEST: usize = 1_504_096;
const MAX_RESPONSE: usize = 263_168;

fn refused() -> fdo::Error {
    fdo::Error::AccessDenied("controller request refused".into())
}
fn unavailable() -> fdo::Error {
    fdo::Error::Failed("controller unavailable".into())
}

struct Worker {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Worker {
    fn start() -> Result<Self, fdo::Error> {
        let executable = std::env::current_exe().map_err(|_| unavailable())?;
        let root = executable
            .parent()
            .and_then(|p| p.parent())
            .ok_or_else(unavailable)?;
        let mut command = Command::new(root.join("venv/bin/python3"));
        command
            .args(["-B", "-E", "-s"])
            .arg(root.join("tools/controller_backend.py"))
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LC_ALL", "C")
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        // A worker and its native prompt children have one owned process group.
        // The actual VPN service remains in its own PID-1-managed service group.
        command.process_group(0);
        let mut child = command.spawn().map_err(|_| unavailable())?;
        let input = child.stdin.take().ok_or_else(unavailable)?;
        let output = BufReader::new(child.stdout.take().ok_or_else(unavailable)?);
        Ok(Self {
            child,
            input,
            output,
        })
    }

    async fn rpc(&mut self, request: &serde_json::Value) -> Result<String, fdo::Error> {
        let mut bytes = serde_json::to_vec(request).map_err(|_| refused())?;
        if bytes.len() > MAX_REQUEST {
            return Err(refused());
        }
        bytes.push(b'\n');
        self.input
            .write_all(&bytes)
            .await
            .map_err(|_| unavailable())?;
        self.input.flush().await.map_err(|_| unavailable())?;
        let mut response = Vec::new();
        loop {
            let buffer = self.output.fill_buf().await.map_err(|_| unavailable())?;
            if buffer.is_empty() {
                return Err(unavailable());
            }
            let end = buffer.iter().position(|b| *b == b'\n').map(|i| i + 1);
            let count = end.unwrap_or(buffer.len());
            if response.len().saturating_add(count) > MAX_RESPONSE {
                return Err(unavailable());
            }
            response.extend_from_slice(&buffer[..count]);
            self.output.consume(count);
            if end.is_some() {
                break;
            }
        }
        let value: serde_json::Value =
            serde_json::from_slice(&response).map_err(|_| unavailable())?;
        if value.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            return Err(refused());
        }
        let result = value.get("result").ok_or_else(unavailable)?;
        if result.get("schema").and_then(|v| v.as_u64()) != Some(1) {
            return Err(unavailable());
        }
        serde_json::to_string(result).map_err(|_| unavailable())
    }

    async fn stop(&mut self) {
        if let Some(pid) = self.child.id()
            && matches!(self.child.try_wait(), Ok(None))
        {
            // SAFETY: this still-running owned child's PID cannot have been
            // reused; process_group(0) assigned its PID as its own PGID.
            unsafe {
                libc::kill(-(pid as i32), libc::SIGTERM);
            }
            if tokio::time::timeout(Duration::from_secs(2), self.child.wait())
                .await
                .is_err()
            {
                // SAFETY: a timeout leaves the owned child unreaped/alive.
                unsafe {
                    libc::kill(-(pid as i32), libc::SIGKILL);
                }
                let _ = self.child.wait().await;
            }
        }
    }
}

#[derive(Default)]
struct Controller {
    worker: Mutex<Option<Worker>>,
}

impl Controller {
    async fn worker_request(&self, request: &serde_json::Value) -> fdo::Result<String> {
        let mut worker = self.worker.lock().await;
        if worker.is_none() {
            *worker = Some(Worker::start()?);
        }
        let result = tokio::time::timeout(
            Duration::from_secs(60),
            worker.as_mut().ok_or_else(unavailable)?.rpc(request),
        )
        .await;
        match result {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error @ fdo::Error::AccessDenied(_))) => Err(error),
            _ => {
                if let Some(mut failed) = worker.take() {
                    failed.stop().await;
                }
                Err(unavailable())
            }
        }
    }

    async fn request(
        &self,
        connection: &Connection,
        header: Header<'_>,
        method: &str,
        value: serde_json::Value,
        manage: bool,
    ) -> fdo::Result<String> {
        let sender = header.sender().ok_or_else(refused)?.as_str().to_owned();
        let bus = Proxy::new(
            connection,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )
        .await
        .map_err(|_| refused())?;
        let uid: u32 = bus
            .call("GetConnectionUnixUser", &(sender.as_str(),))
            .await
            .map_err(|_| refused())?;
        let bus_id: String = bus.call("GetId", &()).await.map_err(|_| refused())?;
        let polkit = Proxy::new(
            connection,
            "org.freedesktop.PolicyKit1",
            "/org/freedesktop/PolicyKit1/Authority",
            "org.freedesktop.PolicyKit1.Authority",
        )
        .await
        .map_err(|_| refused())?;
        let mut identity = HashMap::new();
        identity.insert("name", Variant::from(sender.as_str()));
        let subject = ("system-bus-name", identity);
        let caller = serde_json::json!({"bus_id": bus_id, "name": sender, "uid": uid});
        let mut details = HashMap::<String, String>::new();
        if manage {
            // Fetch only the caller-owned stored plan, over the inherited pipe.
            // Do not hold the worker mutex while the native agent asks the user:
            // progress and cancellation must remain responsive during that wait.
            let raw = self
                .worker_request(&serde_json::json!({
                    "caller": caller, "method": "GetPlan", "value": value
                }))
                .await?;
            let plan = serde_json::from_str(&raw).map_err(|_| unavailable())?;
            details.insert("polkit.message".into(), review_message(&plan)?);
        }
        let action = if manage {
            "org.cypherpunk_vpn.manage"
        } else {
            "org.cypherpunk_vpn.observe"
        };
        let (authorized, _, _): (bool, bool, HashMap<String, String>) = polkit
            .call(
                "CheckAuthorization",
                &(subject, action, details, u32::from(manage), ""),
            )
            .await
            .map_err(|_| refused())?;
        if !authorized {
            return Err(refused());
        }
        // A disconnected unique sender cannot inherit the authorization after a
        // different process obtains a new name. Check it is still on this bus.
        let still_uid: u32 = bus
            .call("GetConnectionUnixUser", &(sender.as_str(),))
            .await
            .map_err(|_| refused())?;
        if uid != still_uid {
            return Err(refused());
        }
        self.worker_request(
            &serde_json::json!({"caller": caller, "method": method, "value": value}),
        )
        .await
    }
}

fn review_message(plan: &serde_json::Value) -> fdo::Result<String> {
    fn text(value: &serde_json::Value) -> fdo::Result<&str> {
        let text = value.as_str().ok_or_else(refused)?;
        // No agent markup, control characters or Polkit variable expansions may
        // be smuggled into the native prompt by a malformed backend result.
        if text.is_empty()
            || text.len() > 1024
            || text.chars().any(char::is_control)
            || text.contains(['<', '>', '&'])
            || text.contains("$(")
        {
            return Err(refused());
        }
        Ok(text)
    }
    let summary = text(&plan["summary"])?;
    let digest = text(&plan["input_digest"])?;
    if !valid_id(digest) {
        return Err(refused());
    }
    let effects = plan["effects"].as_array().ok_or_else(refused)?;
    if effects.is_empty() || effects.len() > 16 {
        return Err(refused());
    }
    let mut message = format!("Approve this cypherpunk_vpn action:\n{summary}\n");
    for effect in effects {
        message.push_str(&format!("\n• {}", text(effect)?));
    }
    message.push_str(&format!("\n\nAction SHA-256: {digest}"));
    if message.len() > 8192 {
        return Err(refused());
    }
    Ok(message)
}

fn valid_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|v| v.is_ascii_hexdigit() && !v.is_ascii_uppercase())
}

#[zbus::interface(name = "org.cypherpunk_vpn.Controller1")]
impl Controller {
    async fn get_snapshot(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<String> {
        self.request(
            connection,
            header,
            "GetSnapshot",
            serde_json::Value::Null,
            false,
        )
        .await
    }
    async fn get_setup(
        &self,
        branch: &str,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<String> {
        if !matches!(branch, "create" | "join") {
            return Err(refused());
        }
        self.request(connection, header, "GetSetup", branch.into(), false)
            .await
    }
    async fn search_providers(
        &self,
        query: &str,
        cursor: &str,
        filter: &str,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<String> {
        if query.len() > 256
            || query.chars().any(|c| c < ' ' || c == '\u{7f}')
            || cursor.len() > 512
            || !matches!(
                filter,
                "all" | "reviewed_recipes" | "unreviewed" | "unavailable_non_compute"
            )
        {
            return Err(refused());
        }
        self.request(
            connection,
            header,
            "SearchProviders",
            serde_json::json!({"query": query, "cursor": if cursor.is_empty() { None } else { Some(cursor) }, "filter": filter}),
            false,
        )
        .await
    }
    async fn preview_action(
        &self,
        request: &str,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<String> {
        if request.len() > 1_500_000 {
            return Err(refused());
        }
        self.request(connection, header, "PreviewAction", request.into(), false)
            .await
    }
    async fn apply_action(
        &self,
        id: &str,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<String> {
        if !valid_id(id) {
            return Err(refused());
        }
        self.request(connection, header, "ApplyAction", id.into(), true)
            .await
    }
    async fn get_operation(
        &self,
        id: &str,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<String> {
        if !valid_id(id) {
            return Err(refused());
        }
        self.request(connection, header, "GetOperation", id.into(), false)
            .await
    }
    async fn cancel_operation(
        &self,
        id: &str,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<String> {
        if !valid_id(id) {
            return Err(refused());
        }
        self.request(connection, header, "CancelOperation", id.into(), false)
            .await
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // SAFETY: geteuid has no memory preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err("system controller requires root".into());
    }
    // SAFETY: umask only changes this new service process's file-creation mask.
    unsafe {
        libc::umask(0o077);
    }
    let _connection = zbus::connection::Builder::address("unix:path=/run/dbus/system_bus_socket")
        .name(NAME)
        .serve_at(OBJECT, Controller::default())
        .build()
        .await?;
    tokio::signal::ctrl_c().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trusted_review_includes_exact_effects_and_digest() {
        let plan = serde_json::json!({"summary":"Import verified route", "effects":["Operator SHA-256: abc", "Keep the traffic guard"], "input_digest":"a".repeat(64)});
        let message = review_message(&plan).unwrap();
        assert!(message.contains("Operator SHA-256: abc"));
        assert!(message.contains(&"a".repeat(64)));
    }
    #[test]
    fn trusted_review_refuses_prompt_spoofing_and_unbounded_fields() {
        for effect in [
            "$(device_file)".to_owned(),
            "<b>Approve</b>".into(),
            "two\nlines".into(),
            "x".repeat(1025),
        ] {
            let plan = serde_json::json!({"summary":"Review", "effects":[effect], "input_digest":"a".repeat(64)});
            assert!(review_message(&plan).is_err());
        }
    }
}
