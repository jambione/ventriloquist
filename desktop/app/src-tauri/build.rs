// Declares the app's own commands so that each gets a permission
// (`allow-<command>`) and the webview may call only the ones granted in
// `capabilities/main.json`.
fn main() {
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "snapshot",
            "forget_peer",
            "set_log_dir",
            "set_name",
            "cancel_pairing",
            "open_log_folder",
            "pick_log_dir",
            "copy_text",
        ]),
    ))
    .expect("tauri build script failed");
}
