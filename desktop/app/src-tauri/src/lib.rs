//! Ventriloquist desktop app (SPEC §6): runs `vq-host-core` with the BLE
//! central transport, forwards every [`HostEvent`] to the web view as one
//! typed JSON Tauri event ([`HOST_EVENT`]), and turns UI actions into
//! [`HostCommand`]s.
//!
//! The web view gets only the commands below (see `build.rs` and
//! `capabilities/main.json`); the clipboard, the folder picker and the
//! file manager are driven from Rust, so it needs no plugin permissions.
//! The web view never supplies a path: the folder picker itself sends the
//! chosen folder to the host (W7).

#![forbid(unsafe_code)]

use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tauri::{AppHandle, Emitter, Manager, RunEvent, State, UserAttentionType};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_opener::OpenerExt;
use tokio::sync::{oneshot, Notify};
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

/// Longest string accepted from the web view for a name or a peer id.
const MAX_ARG_BYTES: usize = 4096;

/// Longest text `copy_text` accepts: above the protocol's 32,000-byte
/// utterance limit, with room for an edited entry.
const MAX_COPY_BYTES: usize = 65_536;

/// Events that may be in flight to the web view (emitted, not yet
/// acknowledged with `ack_events`). Beyond this the forwarder stops
/// draining the host's bounded, coalescing event channel, so a stalled page
/// pushes back on the core instead of growing a queue here (R6).
const EVENT_WINDOW: usize = 256;

/// If the page acknowledges nothing for this long while the window is full,
/// assume the acknowledgements were lost (page reload) and carry on.
const ACK_STALL: Duration = Duration::from_secs(5);

/// Flow control between the event forwarder and the page.
#[derive(Default)]
struct Flow {
    in_flight: AtomicUsize,
    changed: Notify,
}

impl Flow {
    fn acked(&self, n: usize) {
        let mut cur = self.in_flight.load(Ordering::SeqCst);
        while let Err(seen) = self.in_flight.compare_exchange(
            cur,
            cur.saturating_sub(n),
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            cur = seen;
        }
        self.changed.notify_one();
    }

    fn reset(&self) {
        self.in_flight.store(0, Ordering::SeqCst);
        self.changed.notify_one();
    }
}

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
fn snapshot(host: State<'_, Host>, flow: State<'_, Flow>) -> Result<(), String> {
    // The page (re)loaded: acknowledgements for events sent to the previous
    // page will never come.
    flow.reset();
    host.send(HostCommand::Snapshot)
}

/// The page handled `count` events (flow control, see [`EVENT_WINDOW`]).
#[tauri::command]
fn ack_events(flow: State<'_, Flow>, count: u32) {
    flow.acked(count as usize);
}

#[tauri::command]
fn forget_peer(host: State<'_, Host>, device_id: String) -> Result<(), String> {
    let device_id = Uuid::parse_str(&device_id).map_err(|_| "invalid device id".to_string())?;
    host.send(HostCommand::ForgetPeer { device_id })
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

/// Whether `p` is (inside) a macOS bundle or another package directory,
/// which the OS would launch instead of reveal.
fn is_package_path(p: &Path) -> bool {
    const PACKAGES: &[&str] = &[
        "app", "bundle", "framework", "plugin", "kext", "xpc", "appex", "pkg", "prefpane",
        "saver", "workflow", "action", "command",
    ];
    p.components().any(|c| match c {
        Component::Normal(n) => Path::new(n)
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| PACKAGES.iter().any(|k| k.eq_ignore_ascii_case(e))),
        _ => false,
    })
}

/// Windows network paths (`\\server\share`, `//server/share`, `\\?\UNC\…`):
/// writing a log there would send NTLM credentials to the server.
fn is_unc_path(p: &Path) -> bool {
    let s = p.to_string_lossy();
    let b = s.as_bytes();
    let slash = |c: u8| c == b'\\' || c == b'/';
    if b.len() >= 2 && slash(b[0]) && slash(b[1]) {
        // `\\?\C:\…` is a local verbatim path; everything else is remote.
        let local_verbatim = b.len() >= 6
            && b[2] == b'?'
            && slash(b[3])
            && b[4].is_ascii_alphabetic()
            && b[5] == b':';
        return !local_verbatim;
    }
    false
}

/// Why `p` may not be used or opened as the log folder, if so.
fn refuse_folder(p: &Path) -> Option<&'static str> {
    if is_package_path(p) {
        Some("that is an application or package, not a regular folder")
    } else if cfg!(windows) && is_unc_path(p) {
        Some("network folders are not supported")
    } else {
        None
    }
}

/// Open the current log directory in Finder / Explorer. Only the folder the
/// host reports is opened; it must exist and must not be a bundle or (on
/// Windows) a network path. Runs off the main thread: `stat` on a dead
/// network share or sleeping disk can block for a long time.
#[tauri::command]
async fn open_log_folder(app: AppHandle, host: State<'_, Host>) -> Result<(), String> {
    let dir = host
        .lock()
        .log_dir
        .clone()
        .ok_or_else(|| "the log folder is not known yet".to_string())?;
    if let Some(why) = refuse_folder(&dir) {
        return Err(format!("{}: {why}", dir.display()));
    }
    let shown = dir.clone();
    let exists = tauri::async_runtime::spawn_blocking(move || shown.is_dir())
        .await
        .map_err(|e| e.to_string())?;
    if !exists {
        return Err(format!("{} does not exist", dir.display()));
    }
    // Name the file manager so the OS never picks another handler.
    let with = if cfg!(target_os = "macos") {
        Some("Finder")
    } else if cfg!(windows) {
        Some("explorer")
    } else {
        None
    };
    app.opener()
        .open_path(dir.to_string_lossy(), with)
        .map_err(|e| e.to_string())
}

/// Show a folder picker and make the chosen folder the log folder (the
/// host persists it). Resolves to `false` when the user cancelled. The web
/// view supplies no path.
#[tauri::command]
async fn pick_log_dir(app: AppHandle, host: State<'_, Host>) -> Result<bool, String> {
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
        return Ok(false);
    };
    let path = picked.into_path().map_err(|e| e.to_string())?;
    if let Some(why) = refuse_folder(&path) {
        return Err(format!("{}: {why}", path.display()));
    }
    host.send(HostCommand::SetLogDir { path })?;
    Ok(true)
}

/// Put exactly `text` on the clipboard (nothing added, nothing trimmed).
#[tauri::command]
fn copy_text(app: AppHandle, text: String) -> Result<(), String> {
    if text.len() > MAX_COPY_BYTES {
        return Err("the text is too long to copy".into());
    }
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
        let flow = app.state::<Flow>();
        loop {
            // Backpressure (R6): with a full window, leave events in the
            // host's bounded, coalescing channel until the page catches up.
            while flow.in_flight.load(Ordering::SeqCst) >= EVENT_WINDOW {
                let wait = tokio::time::timeout(ACK_STALL, flow.changed.notified()).await;
                if wait.is_err() {
                    log::warn!("the page acknowledged no events for {ACK_STALL:?}; resuming");
                    flow.reset();
                }
            }
            let Some(ev) = events.recv().await else { break };
            if let HostEvent::Started { log_dir, .. }
            | HostEvent::Snapshot { log_dir, .. }
            | HostEvent::ConfigChanged { log_dir, .. } = &ev
            {
                app.state::<Host>().lock().log_dir = Some(log_dir.clone());
            }
            if matches!(ev, HostEvent::PairingCodeShown { .. }) {
                draw_attention(&app);
            }
            // Before the page listens (or while it reloads) events are
            // dropped; the page asks for a snapshot when it loads and
            // retries until one arrives.
            match app.emit_to(MAIN_WINDOW, HOST_EVENT, &ev) {
                Ok(()) => {
                    flow.in_flight.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) => log::warn!("cannot forward a host event: {e}"),
            }
        }
    });
    Ok(())
}

/// A pairing code is waiting: make the window visible (without stealing
/// focus) and ask the OS to flag it, so that a minimized window does not
/// let the 120 s code run out unseen.
fn draw_attention(app: &AppHandle) {
    if let Some(w) = app.get_webview_window(MAIN_WINDOW) {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.request_user_attention(Some(UserAttentionType::Informational));
    }
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
    /// Debug for this app and the core; Info for dependencies (their debug
    /// output, e.g. btleplug's, is noise).
    fn enabled(&self, m: &log::Metadata<'_>) -> bool {
        let ours = m.target().starts_with("ventriloquist") || m.target().starts_with("vq_");
        ours || m.level() <= log::Level::Info
    }
    fn log(&self, r: &log::Record<'_>) {
        if !self.enabled(r.metadata()) {
            return;
        }
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
        // First: a second launch must exit before anything else starts, and
        // focus the running instance instead.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(w) = app.get_webview_window(MAIN_WINDOW) {
                let _ = w.unminimize();
                let _ = w.show();
                let _ = w.set_focus();
            }
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(Host::default())
        .manage(Flow::default())
        .invoke_handler(tauri::generate_handler![
            snapshot,
            forget_peer,
            ack_events,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundles_and_packages_are_refused_regular_folders_are_not() {
        for p in ["/Applications/X.app", "/Applications/X.APP/Contents", "/a/b.bundle/c", "/a/b.framework"] {
            assert!(is_package_path(Path::new(p)), "{p}");
        }
        for p in ["/Users/me/Documents/Ventriloquist", "/tmp/app", "/tmp/my.app.logs", "/tmp/a.b/c"] {
            assert!(!is_package_path(Path::new(p)), "{p}");
        }
    }

    #[test]
    fn unc_paths_are_detected() {
        for p in [r"\\host\share", "//host/share", r"\\?\UNC\host\share", r"\\.\pipe\x"] {
            assert!(is_unc_path(Path::new(p)), "{p}");
        }
        for p in [r"C:\Users\me", r"\\?\C:\Users\me", "/Users/me", "relative/path"] {
            assert!(!is_unc_path(Path::new(p)), "{p}");
        }
    }

    #[test]
    fn flow_control_counts_down_and_never_underflows() {
        let f = Flow::default();
        f.in_flight.store(3, Ordering::SeqCst);
        f.acked(2);
        assert_eq!(f.in_flight.load(Ordering::SeqCst), 1);
        f.acked(10);
        assert_eq!(f.in_flight.load(Ordering::SeqCst), 0);
        f.in_flight.store(5, Ordering::SeqCst);
        f.reset();
        assert_eq!(f.in_flight.load(Ordering::SeqCst), 0);
    }
}
