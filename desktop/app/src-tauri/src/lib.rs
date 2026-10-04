//! Ventriloquist desktop app (SPEC §6): runs `vq-host-core` with the BLE
//! central transport, forwards every [`HostEvent`] to the web view as one
//! typed JSON Tauri event ([`HOST_EVENT`]), and turns UI actions into
//! [`HostCommand`]s.
//!
//! The web view gets only the commands below (see `build.rs` and
//! `capabilities/main.json`); the clipboard, the folder picker and the
//! file manager are driven from Rust, so it needs no plugin permissions.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tauri::{AppHandle, Emitter, Manager, RunEvent, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_opener::OpenerExt;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use uuid::Uuid;
use vq_host_core::config::default_config_dir;
use vq_host_core::transport::ble::BleCentralTransport;
use vq_host_core::{spawn_host, CoreOptions, HostCommand, HostEvent, HostHandle, SystemClock};

/// The Tauri event that carries every host event (`HostEvent` as JSON,
/// tagged by `"event"`; desktop/core/README.md).
pub const HOST_EVENT: &str = "host-event";

/// The window that shows the UI.
const MAIN_WINDOW: &str = "main";

/// How long to wait for the host to stop when the app quits. The host
/// itself waits at most 3 s for the transport, 2 s for queued log writes
/// and 1 s to flush events.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(8);

/// Longest string accepted from the web view for a name or a path.
const MAX_ARG_BYTES: usize = 4096;

#[derive(Default)]
struct HostSlot {
    handle: Option<HostHandle>,
    task: Option<JoinHandle<()>>,
    /// Why the host could not start (e.g. an unreadable identity file).
    error: Option<String>,
    /// Current log directory, as last reported by the host.
    log_dir: Option<PathBuf>,
}

/// The running host, shared by the commands.
#[derive(Default)]
struct Host(Mutex<HostSlot>);

impl Host {
    fn lock(&self) -> MutexGuard<'_, HostSlot> {
        // A panic while holding the lock leaves plain data behind; keep going.
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn send(&self, cmd: HostCommand) -> Result<(), String> {
        let slot = self.lock();
        if let Some(e) = &slot.error {
            return Err(e.clone());
        }
        match &slot.handle {
            Some(h) if h.send(cmd) => Ok(()),
            _ => Err("the Ventriloquist host is not running".into()),
        }
    }
}

fn check_len(what: &str, s: &str) -> Result<(), String> {
    if s.len() > MAX_ARG_BYTES {
        Err(format!("{what} is too long"))
    } else {
        Ok(())
    }
}

/// Ask the host for a `snapshot` event (sent on [`HOST_EVENT`]).
#[tauri::command]
fn snapshot(host: State<'_, Host>) -> Result<(), String> {
    host.send(HostCommand::Snapshot)
}

#[tauri::command]
fn forget_peer(host: State<'_, Host>, device_id: String) -> Result<(), String> {
    let device_id = Uuid::parse_str(&device_id).map_err(|_| "invalid device id".to_string())?;
    host.send(HostCommand::ForgetPeer { device_id })
}

/// The host refuses a relative path (with a `storage_warning`).
#[tauri::command]
fn set_log_dir(host: State<'_, Host>, path: String) -> Result<(), String> {
    check_len("the path", &path)?;
    host.send(HostCommand::SetLogDir {
        path: PathBuf::from(path),
    })
}

/// An empty name resets to the host name; the host normalises it.
#[tauri::command]
fn set_name(host: State<'_, Host>, name: String) -> Result<(), String> {
    check_len("the name", &name)?;
    host.send(HostCommand::SetName { name })
}

#[tauri::command]
fn cancel_pairing(host: State<'_, Host>, peer: String) -> Result<(), String> {
    check_len("the peer id", &peer)?;
    host.send(HostCommand::CancelPairing { peer })
}

/// Open the current log directory in Finder / Explorer.
#[tauri::command]
fn open_log_folder(app: AppHandle, host: State<'_, Host>) -> Result<(), String> {
    let dir = host
        .lock()
        .log_dir
        .clone()
        .ok_or_else(|| "the log folder is not known yet".to_string())?;
    if !dir.is_dir() {
        return Err(format!("{} does not exist", dir.display()));
    }
    app.opener()
        .open_path(dir.to_string_lossy(), None::<&str>)
        .map_err(|e| e.to_string())
}

/// Show a folder picker; resolves to the chosen absolute path, or `None`.
/// It does not change the setting: the UI calls `set_log_dir` with it.
#[tauri::command]
async fn pick_log_dir(app: AppHandle, host: State<'_, Host>) -> Result<Option<String>, String> {
    let start = host.lock().log_dir.clone();
    let (tx, rx) = oneshot::channel();
    let mut dialog = app.dialog().file().set_title("Choose the log folder");
    if let Some(dir) = start.filter(|d| d.is_dir()) {
        dialog = dialog.set_directory(dir);
    }
    dialog.pick_folder(move |picked| {
        let _ = tx.send(picked);
    });
    let Some(picked) = rx.await.map_err(|_| "the folder picker closed".to_string())? else {
        return Ok(None);
    };
    let path = picked.into_path().map_err(|e| e.to_string())?;
    path.into_os_string()
        .into_string()
        .map(Some)
        .map_err(|_| "that folder's path is not valid Unicode".to_string())
}

/// Put exactly `text` on the clipboard (nothing added, nothing trimmed).
#[tauri::command]
fn copy_text(app: AppHandle, text: String) -> Result<(), String> {
    app.clipboard().write_text(text).map_err(|e| e.to_string())
}

/// Start the host and the task that forwards its events to the web view.
fn start_host(app: &AppHandle) -> std::io::Result<()> {
    let opts = CoreOptions {
        config_dir: default_config_dir(),
        log_dir_override: None,
        name_override: None,
        clock: Arc::new(SystemClock::new()),
    };
    let (handle, mut events, task) = {
        // `spawn_host` spawns onto the current tokio runtime: Tauri's.
        let rt = tauri::async_runtime::handle();
        let _guard = rt.inner().enter();
        spawn_host(opts, Box::new(BleCentralTransport::new()))?
    };
    {
        let host = app.state::<Host>();
        let mut slot = host.lock();
        slot.handle = Some(handle);
        slot.task = Some(task);
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(ev) = events.recv().await {
            if let HostEvent::Started { log_dir, .. }
            | HostEvent::Snapshot { log_dir, .. }
            | HostEvent::ConfigChanged { log_dir, .. } = &ev
            {
                app.state::<Host>().lock().log_dir = Some(log_dir.clone());
            }
            // Before the page listens (or while it reloads) events are
            // dropped; the page asks for a snapshot when it loads.
            if let Err(e) = app.emit_to(MAIN_WINDOW, HOST_EVENT, &ev) {
                log::warn!("cannot forward a host event: {e}");
            }
        }
    });
    Ok(())
}

/// Stop the host and wait (bounded) for it to finish: pending log writes
/// are flushed and BLE connections are closed.
fn stop_host(app: &AppHandle) {
    let (handle, task) = {
        let host = app.state::<Host>();
        let mut slot = host.lock();
        (slot.handle.take(), slot.task.take())
    };
    if let Some(h) = handle {
        h.send(HostCommand::Shutdown);
    }
    if let Some(task) = task {
        let done = tauri::async_runtime::block_on(tokio::time::timeout(SHUTDOWN_TIMEOUT, task));
        if done.is_err() {
            log::warn!("the host did not stop within {SHUTDOWN_TIMEOUT:?}");
        }
    }
}

struct StderrLog;

impl log::Log for StderrLog {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, r: &log::Record<'_>) {
        eprintln!("[{}] {}", r.level(), r.args());
    }
    fn flush(&self) {}
}

/// Run the app.
pub fn run() {
    if std::env::var_os("VQ_LOG").is_some() {
        static LOGGER: StderrLog = StderrLog;
        if log::set_logger(&LOGGER).is_ok() {
            log::set_max_level(log::LevelFilter::Debug);
        }
    }
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(Host::default())
        .invoke_handler(tauri::generate_handler![
            snapshot,
            forget_peer,
            set_log_dir,
            set_name,
            cancel_pairing,
            open_log_folder,
            pick_log_dir,
            copy_text,
        ])
        .setup(|app| {
            if let Err(e) = start_host(app.handle()) {
                // Keep the window: the UI shows the reason (the `snapshot`
                // command fails with it).
                log::error!("cannot start the host: {e}");
                app.state::<Host>().lock().error = Some(e.to_string());
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building the Ventriloquist app");
    app.run(|app, event| {
        if let RunEvent::Exit = event {
            stop_host(app);
        }
    });
}
