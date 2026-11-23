//! Unprivileged, bounded D-Bus adapter. No shell, filesystem API, PIN or cloud token
//! is exposed to the WebView. Privileged authorization remains in the root broker.
//! The own-servers side of setup runs the installed user helper (`operator.rs`) with
//! fixed, checked arguments only.

mod operator;

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

// The GUI's observation commands (tools/controller_extension.py): reads
// only - no plan, no operation, no user input crosses this boundary.
#[tauri::command]
async fn streaming_eligibility(bridge: State<'_, Bridge>) -> Result<String, String> {
    bridge.call("GetStreamingEligibility", &()).await
}

#[tauri::command]
async fn multihop_presets(bridge: State<'_, Bridge>) -> Result<String, String> {
    bridge.call("GetMultihopPresets", &()).await
}

#[tauri::command]
async fn autoconnect_policy(bridge: State<'_, Bridge>) -> Result<String, String> {
    bridge.call("GetAutoconnectPolicy", &()).await
}

#[tauri::command]
async fn get_setup(branch: String, bridge: State<'_, Bridge>) -> Result<String, String> {
    if !matches!(branch.as_str(), "create" | "join") {
        return Err("invalid_setup_branch".into());
    }
    bridge.call("GetSetup", &(branch,)).await
}

#[tauri::command]
async fn provider_search(
    query: String,
    cursor: Option<String>,
    filter: String,
    bridge: State<'_, Bridge>,
) -> Result<String, String> {
    if query.len() > 256 || query.chars().any(|c| c < ' ' || c == '\u{7f}') {
        return Err("invalid_search_query".into());
    }
    if !matches!(
        filter.as_str(),
        "all" | "reviewed_recipes" | "unreviewed" | "unavailable_non_compute"
    ) {
        return Err("invalid_search_filter".into());
    }
    if cursor
        .as_ref()
        .is_some_and(|c| c.is_empty() || c.len() > 512)
    {
        return Err("invalid_provider_cursor".into());
    }
    bridge
        .call(
            "SearchProviders",
            &(query, cursor.unwrap_or_default(), filter),
        )
        .await
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

// The own-servers side of setup (tools/desktop_setup.py, as this user).
#[tauri::command]
async fn operator_state() -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(|| operator::call(&["state"]))
        .await
        .map_err(|_| "helper_unavailable")?
}

#[tauri::command]
async fn operator_provider(command: String, key: String) -> Result<String, String> {
    if !matches!(command.as_str(), "check" | "add" | "remove") {
        return Err("invalid_provider_command".into());
    }
    operator::provider_key(&key)?;
    tauri::async_runtime::spawn_blocking(move || operator::call(&[command.as_str(), key.as_str()]))
        .await
        .map_err(|_| "helper_unavailable")?
}

/// Renew the cloud sign-in one recorded server uses (the helper opens the browser).
#[tauri::command]
async fn operator_signin(server: String) -> Result<String, String> {
    operator::server_name(&server)?;
    tauri::async_runtime::spawn_blocking(move || operator::call(&["signin", server.as_str()]))
        .await
        .map_err(|_| "helper_unavailable")?
}

/// The first-launch agreement: whether this version is accepted, or record acceptance.
#[tauri::command]
async fn operator_agreement(command: String, version: String) -> Result<String, String> {
    if !matches!(command.as_str(), "state" | "accept") {
        return Err("invalid_agreement_command".into());
    }
    operator::agreement_version(&version)?;
    tauri::async_runtime::spawn_blocking(move || {
        operator::call(&["agreement", command.as_str(), version.as_str()])
    })
    .await
    .map_err(|_| "helper_unavailable")?
}

/// "Reject and quit" on the agreement: close the app.
#[tauri::command]
fn quit_app(app: tauri::AppHandle) {
    app.exit(0);
}

#[tauri::command]
fn operator_build(
    order: Vec<String>,
    hours: u8,
    request: String,
    builds: State<'_, operator::Builds>,
) -> Result<(), String> {
    builds.start(order, hours, request)
}

#[tauri::command]
async fn operator_export(request: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || operator::export(&request))
        .await
        .map_err(|_| "helper_unavailable")?
}

#[tauri::command]
fn operator_build_status(builds: State<'_, operator::Builds>) -> Result<String, String> {
    builds.status()
}

pub fn run() {
    // SAFETY: geteuid has no arguments or memory preconditions.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("Run the desktop app as your ordinary user.");
        return;
    }
    tauri::Builder::default()
        .manage(Bridge::default())
        .manage(operator::Builds::default())
        .invoke_handler(tauri::generate_handler![
            get_snapshot,
            get_setup,
            preview_action,
            apply_action,
            get_operation,
            cancel_operation,
            provider_search,
            streaming_eligibility,
            multihop_presets,
            autoconnect_policy,
            operator_state,
            operator_provider,
            operator_build,
            operator_build_status,
            operator_export,
            operator_signin,
            operator_agreement,
            quit_app
        ])
        .run(tauri::generate_context!())
        .expect("cypherpunk_vpn desktop application");
}
