//! Unprivileged, bounded D-Bus adapter. No shell, filesystem API, PIN or cloud token
//! is exposed to the WebView. Privileged authorization remains in the root broker.

use tauri::State;
use tokio::sync::Mutex;

const SERVICE: &str = "org.cypherpunk_vpn.Controller1";
const OBJECT: &str = "/org/cypherpunk_vpn/Controller1";
const RESPONSE_LIMIT: usize = 256 * 1024;

#[derive(Default)]
struct Bridge {
    connection: Mutex<Option<zbus::Connection>>,
}

impl Bridge {
    async fn call<B>(&self, method: &str, body: &B) -> Result<String, String>
    where
        B: serde::Serialize + zbus::DynamicType + Sync,
    {
        let connection = {
            let mut slot = self.connection.lock().await;
            if slot.is_none() {
                let connection =
                    zbus::connection::Builder::address("unix:path=/run/dbus/system_bus_socket")
                        .build()
                        .await
                        .map_err(|_| "controller_unavailable")?;
                *slot = Some(connection);
            }
            slot.as_ref().ok_or("controller_unavailable")?.clone()
        };
        let proxy = zbus::Proxy::new(&connection, SERVICE, OBJECT, SERVICE)
            .await
            .map_err(|_| "controller_unavailable")?;
        let result: Result<String, _> = proxy.call(method, body).await;
        let raw = match result {
            Ok(value) => value,
            Err(_) => {
                // Refusal or dismissed authentication does not end a bus
                // identity. Retain it so its owned operation stays cancellable.
                // Only a genuinely closed connection requires a new name.
                if connection.is_closed() {
                    let mut slot = self.connection.lock().await;
                    if slot
                        .as_ref()
                        .is_some_and(|current| current.unique_name() == connection.unique_name())
                    {
                        *slot = None;
                    }
                }
                return Err("controller_request_failed".into());
            }
        };
        if raw.len() > RESPONSE_LIMIT {
            return Err("controller_response_too_large".into());
        }
        let value: serde_json::Value =
            serde_json::from_str(&raw).map_err(|_| "invalid_controller_response")?;
        if value.get("schema").and_then(|x| x.as_u64()) != Some(1) {
            return Err("invalid_controller_schema".into());
        }
        Ok(raw)
    }
}

fn identifier(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|x| x.is_ascii_hexdigit() && !x.is_ascii_uppercase())
    {
        return Err("invalid_operation_identifier".into());
    }
    Ok(())
}

#[tauri::command]
async fn get_snapshot(bridge: State<'_, Bridge>) -> Result<String, String> {
    bridge.call("GetSnapshot", &()).await
}

#[tauri::command]
async fn get_setup(branch: String, bridge: State<'_, Bridge>) -> Result<String, String> {
    if !matches!(branch.as_str(), "create" | "join") {
        return Err("invalid_setup_branch".into());
    }
    bridge.call("GetSetup", &(branch,)).await
}

#[tauri::command]
async fn preview_action(request: String, bridge: State<'_, Bridge>) -> Result<String, String> {
    if request.len() > 1_500_000 {
        return Err("action_too_large".into());
    }
    bridge.call("PreviewAction", &(request,)).await
}

#[tauri::command]
async fn apply_action(id: String, bridge: State<'_, Bridge>) -> Result<String, String> {
    identifier(&id)?;
    bridge.call("ApplyAction", &(id,)).await
}

#[tauri::command]
async fn get_operation(id: String, bridge: State<'_, Bridge>) -> Result<String, String> {
    identifier(&id)?;
    bridge.call("GetOperation", &(id,)).await
}

#[tauri::command]
async fn cancel_operation(id: String, bridge: State<'_, Bridge>) -> Result<String, String> {
    identifier(&id)?;
    bridge.call("CancelOperation", &(id,)).await
}

pub fn run() {
    // SAFETY: geteuid has no arguments or memory preconditions.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("Run the desktop app as your ordinary user.");
        return;
    }
    tauri::Builder::default()
        .manage(Bridge::default())
        .invoke_handler(tauri::generate_handler![
            get_snapshot,
            get_setup,
            preview_action,
            apply_action,
            get_operation,
            cancel_operation
        ])
        .run(tauri::generate_context!())
        .expect("cypherpunk_vpn desktop application");
}
