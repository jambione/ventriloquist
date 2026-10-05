// Declares the app's own commands so that each gets a permission
// (`allow-<command>`) and the webview may call only the ones granted in
// `capabilities/main.json`.
/// Short git commit for the About/Settings label: GITHUB_SHA on CI, else
/// `git rev-parse`, else "unknown".
fn commit() -> String {
    let short = |s: &str| s.trim().chars().take(7).collect::<String>();
    if let Ok(sha) = std::env::var("GITHUB_SHA") {
        if !sha.trim().is_empty() {
            return short(&sha);
        }
    }
    std::process::Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| short(&String::from_utf8_lossy(&o.stdout)))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn main() {
    println!("cargo:rustc-env=VQ_GIT_COMMIT={}", commit());
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    println!("cargo:rerun-if-changed=../../../.git/HEAD");
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
            "clear_all_slots",
            "set_slot_settings",
            "send_to_active",
            "set_hotkey_modifiers",
            "accessibility_status",
            "open_accessibility_settings",
            "diagnostics_info",
            "open_diagnostics_file",
            "open_diagnostics_folder",
            "app_version",
            "relay_settings",
            "set_relay_url",
            "set_owner_token",
            "generate_owner_token",
            "test_relay",
            "reset_relay_room",
            "start_phone_pairing",
            "stop_phone_pairing",
            "qr_svg",
        ]),
    ))
    .expect("tauri build script failed");
}
