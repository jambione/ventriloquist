//! `vq-host`: runs the desktop core headlessly over the TCP dev transport
//! and prints one JSON object per event on stdout (format: README.md in
//! this crate). Reads optional JSON commands, one per line, from stdin.
//!
//! ```text
//! vq-host [--connect HOST:PORT] [--log-dir DIR] [--config-dir DIR] [--name NAME]
//! ```

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use tokio::io::AsyncBufReadExt;
use vq_host_core::config::default_dev_config_dir;
use vq_host_core::transport::tcp::TcpTransport;
use vq_host_core::{spawn_host, CoreOptions, HostCommand, SystemClock};

const USAGE: &str =
    "usage: vq-host [--connect HOST:PORT] [--log-dir DIR] [--config-dir DIR] [--name NAME]\n\
  --connect     phone simulator address (default 127.0.0.1:47800)\n\
  --log-dir     log directory for this run (default: configured, else ~/Documents/Ventriloquist)\n\
  --config-dir  identity / pairing / config directory\n\
                (default: <OS local config dir>/com.ventriloquist.desktop.dev, never the app's)\n\
  --name        display name for this run (default: configured, else host name)\n\
  env VQ_LOG=1  diagnostics on stderr";

struct Args {
    connect: String,
    log_dir: Option<PathBuf>,
    config_dir: Option<PathBuf>,
    name: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        connect: format!("127.0.0.1:{}", vq_protocol::TCP_DEFAULT_PORT),
        log_dir: None,
        config_dir: None,
        name: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--connect" => a.connect = value()?,
            "--log-dir" => a.log_dir = Some(PathBuf::from(value()?)),
            "--config-dir" => a.config_dir = Some(PathBuf::from(value()?)),
            "--name" => a.name = Some(value()?),
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(a)
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

#[tokio::main]
async fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("vq-host: {e}");
            }
            eprintln!("{USAGE}");
            return if e.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            };
        }
    };
    if std::env::var_os("VQ_LOG").is_some() {
        static LOGGER: StderrLog = StderrLog;
        let _ = log::set_logger(&LOGGER);
        log::set_max_level(log::LevelFilter::Debug);
    }
    let opts = CoreOptions {
        config_dir: args.config_dir.unwrap_or_else(default_dev_config_dir),
        log_dir_override: args.log_dir,
        name_override: args.name,
        clock: Arc::new(SystemClock::new()),
        relay: None,
    };
    let (handle, mut events, task) =
        match spawn_host(opts, Box::new(TcpTransport::new(args.connect))) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("vq-host: cannot start: {e}");
                return ExitCode::FAILURE;
            }
        };

    // Commands from stdin (optional). EOF on stdin does not stop the host.
    let cmd_handle = handle.clone();
    tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<HostCommand>(&line) {
                Ok(c) => {
                    cmd_handle.send(c);
                }
                Err(e) => eprintln!("vq-host: bad command: {e}"),
            }
        }
    });

    let printer = tokio::spawn(async move {
        let stdout = std::io::stdout();
        while let Some(ev) = events.recv().await {
            let line = serde_json::to_string(&ev).expect("events serialize");
            let mut out = stdout.lock();
            if writeln!(out, "{line}").and_then(|()| out.flush()).is_err() {
                break;
            }
        }
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            handle.send(HostCommand::Shutdown);
        }
        _ = sigterm() => {
            handle.send(HostCommand::Shutdown);
        }
    }
    let _ = task.await;
    drop(handle);
    let _ = printer.await;
    ExitCode::SUCCESS
}

#[cfg(unix)]
async fn sigterm() {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut s) => {
            s.recv().await;
        }
        Err(_) => std::future::pending::<()>().await,
    }
}

#[cfg(not(unix))]
async fn sigterm() {
    std::future::pending::<()>().await
}
