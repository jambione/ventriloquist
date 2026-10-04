//! Always-on file logging (all OSes). A Windows GUI app has no console, so
//! every run writes `<config dir>/logs/ventriloquist.log`, rotated at
//! [`MAX_BYTES`] and keeping [`KEEP_FILES`] files in total
//! (`ventriloquist.log`, `.1`, `.2`).
//!
//! Info level by default; Debug for this app and the core when `VQ_LOG` is
//! set (which also mirrors the log to stderr). Dependencies are capped at
//! Info: their debug output is noise.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// A log file is rotated when it would grow beyond this.
pub const MAX_BYTES: u64 = 2 * 1024 * 1024;
/// Files kept in total, the current one included.
pub const KEEP_FILES: usize = 3;
/// Directory (inside the config directory) and file name of the log.
pub const LOG_DIR_NAME: &str = "logs";
pub const LOG_FILE_NAME: &str = "ventriloquist.log";

/// `<config dir>/logs/ventriloquist.log`.
pub fn log_path(config_dir: &Path) -> PathBuf {
    config_dir.join(LOG_DIR_NAME).join(LOG_FILE_NAME)
}

fn numbered(path: &Path, n: usize) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}

/// An append-only file that rotates by size.
pub struct RotatingFile {
    path: PathBuf,
    max_bytes: u64,
    keep: usize,
    file: Option<File>,
    size: u64,
}

impl RotatingFile {
    /// Open (append) `path`, creating its directory.
    pub fn open(path: PathBuf, max_bytes: u64, keep: usize) -> std::io::Result<Self> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self { path, max_bytes, keep: keep.max(1), file: Some(file), size })
    }

    fn rotate(&mut self) {
        self.file = None;
        if self.keep > 1 {
            for n in (1..self.keep - 1).rev() {
                let _ = fs::rename(numbered(&self.path, n), numbered(&self.path, n + 1));
            }
            let _ = fs::rename(&self.path, numbered(&self.path, 1));
        }
        self.file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.path)
            .ok();
        self.size = 0;
    }

    /// Append `line` (a newline is added), rotating first when needed.
    pub fn write_line(&mut self, line: &str) {
        let len = line.len() as u64 + 1;
        if self.size > 0 && self.size + len > self.max_bytes {
            self.rotate();
        }
        if self.file.is_none() {
            self.rotate();
        }
        if let Some(f) = &mut self.file {
            if writeln!(f, "{line}").is_ok() {
                self.size += len;
            }
        }
    }
}

struct FileLogger {
    out: Mutex<RotatingFile>,
    debug_ours: bool,
    stderr: bool,
}

fn is_ours(target: &str) -> bool {
    target.starts_with("ventriloquist") || target.starts_with("vq_")
}

impl FileLogger {
    fn allows(&self, level: log::Level, target: &str) -> bool {
        level <= log::Level::Info || (self.debug_ours && is_ours(target))
    }
}

impl log::Log for FileLogger {
    fn enabled(&self, m: &log::Metadata<'_>) -> bool {
        self.allows(m.level(), m.target())
    }

    fn log(&self, r: &log::Record<'_>) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
        let line = format!("{now} {:<5} {} {}", r.level(), r.target(), r.args());
        if self.stderr {
            eprintln!("{line}");
        }
        self.out.lock().unwrap_or_else(|p| p.into_inner()).write_line(&line);
    }

    fn flush(&self) {}
}

/// Install the logger (and a panic hook that logs panics). Returns the log
/// file path, or the reason the file could not be opened (logging then goes
/// to stderr only, if `VQ_LOG` is set).
pub fn init(config_dir: &Path) -> Result<PathBuf, String> {
    let debug_ours = std::env::var_os("VQ_LOG").is_some_and(|v| v != "0" && !v.is_empty());
    let path = log_path(config_dir);
    let file = RotatingFile::open(path.clone(), MAX_BYTES, KEEP_FILES)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let logger = Box::leak(Box::new(FileLogger {
        out: Mutex::new(file),
        debug_ours,
        stderr: std::env::var_os("VQ_LOG").is_some(),
    }));
    log::set_logger(logger).map_err(|e| e.to_string())?;
    log::set_max_level(if debug_ours { log::LevelFilter::Debug } else { log::LevelFilter::Info });
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        log::error!("panic: {info}");
        default_hook(info);
    }));
    Ok(path)
}

/// Best-effort OS version text for the startup banner.
pub fn os_version() -> String {
    let out = |cmd: &mut std::process::Command| {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        cmd.output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
    };
    let detail = if cfg!(target_os = "macos") {
        out(std::process::Command::new("sw_vers").arg("-productVersion"))
    } else if cfg!(windows) {
        out(std::process::Command::new("cmd").args(["/C", "ver"]))
    } else {
        fs::read_to_string("/etc/os-release").ok().and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("PRETTY_NAME="))
                .map(|v| v.trim_matches('"').to_owned())
        })
    };
    format!(
        "{} {} ({})",
        std::env::consts::OS,
        detail.unwrap_or_else(|| "unknown version".into()),
        std::env::consts::ARCH
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vq-log-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn path_is_logs_ventriloquist_log_in_the_config_dir() {
        let p = log_path(Path::new("/c/com.ventriloquist.desktop"));
        assert!(p.ends_with("logs/ventriloquist.log"));
    }

    #[test]
    fn rotates_by_size_and_keeps_three_files() {
        let d = tmp("rot");
        let path = d.join("logs").join("v.log");
        let mut f = RotatingFile::open(path.clone(), 100, 3).unwrap();
        for i in 0..40 {
            f.write_line(&format!("line {i:03} xxxxxxxxxxxxxxxxxxxx"));
        }
        assert!(path.exists());
        assert!(numbered(&path, 1).exists());
        assert!(numbered(&path, 2).exists());
        assert!(!numbered(&path, 3).exists());
        for p in [path.clone(), numbered(&path, 1), numbered(&path, 2)] {
            assert!(fs::metadata(&p).unwrap().len() <= 100, "{}", p.display());
        }
        // The newest line is in the current file; the order is newest first.
        assert!(fs::read_to_string(&path).unwrap().contains("line 039"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn appends_to_an_existing_file_and_counts_its_size() {
        let d = tmp("app");
        let path = d.join("v.log");
        RotatingFile::open(path.clone(), 1000, 3).unwrap().write_line("one");
        let mut f = RotatingFile::open(path.clone(), 1000, 3).unwrap();
        f.write_line("two");
        assert_eq!(fs::read_to_string(&path).unwrap(), "one\ntwo\n");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn debug_only_for_our_crates_and_only_with_vq_log() {
        let mk = |debug_ours| FileLogger {
            out: Mutex::new(
                RotatingFile::open(tmp("lvl").join("v.log"), 1000, 3).unwrap(),
            ),
            debug_ours,
            stderr: false,
        };
        let off = mk(false);
        assert!(off.allows(log::Level::Info, "btleplug"));
        assert!(!off.allows(log::Level::Debug, "vq_host_core::x"));
        let on = mk(true);
        assert!(on.allows(log::Level::Debug, "vq_host_core::x"));
        assert!(on.allows(log::Level::Debug, "ventriloquist_desktop_lib"));
        assert!(!on.allows(log::Level::Debug, "btleplug"));
        let _ = fs::remove_dir_all(tmp("lvl"));
    }
}
