// Declares the app's own commands so that each gets a permission
// (`allow-<command>`) and the webview may call only the ones granted in
// `capabilities/main.json`.
fn main() {
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "snapshot",
            "forget_peer",
            "ack_events",
            "set_name",
            "cancel_pairing",
            "open_log_folder",
            "pick_log_dir",
            "copy_text",
            "slots_snapshot",
            "select_slot",
            "unbind_slot",
            "set_slot_settings",
            "send_to_active",
            "set_hotkey_modifiers",
            "accessibility_status",
            "open_accessibility_settings",
        ]),
    ))
    .expect("tauri build script failed");
}
