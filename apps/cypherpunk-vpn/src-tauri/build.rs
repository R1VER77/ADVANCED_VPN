fn main() {
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "get_snapshot",
            "get_setup",
            "preview_action",
            "apply_action",
            "get_operation",
            "cancel_operation",
        ]),
    ))
    .expect("Tauri application ACL generation");
}
