//! `vq-host`: runs the desktop core headlessly over the TCP dev transport
//! and prints one JSON object per event on stdout (format: README.md in
//! this crate). Reads optional JSON commands, one per line, from stdin.
//!
//! ```text
//! vq-host [--connect HOST:PORT | --relay URL [--owner-token-file FILE]]
//!         [--log-dir DIR] [--config-dir DIR] [--name NAME]
//! ```

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use tokio::io::AsyncBufReadExt;
use vq_host_core::config::default_dev_config_dir;
use vq_host_core::relay_room::RelayRoomStore;
use vq_host_core::transport::relay::{RelayOptions, RelayTransport};
use vq_host_core::transport::tcp::TcpTransport;
use vq_host_core::transport::Transport;
use vq_host_core::{spawn_host, CoreOptions, HostCommand, SystemClock};

const USAGE: &str =
    "usage: vq-host [--connect HOST:PORT | --relay URL [--owner-token-file FILE]] [--log-dir DIR] [--config-dir DIR] [--name NAME]\n\
  --connect     phone simulator address (default 127.0.0.1:47800)\n\
  --relay       use the relay transport at URL (http:// allowed for loopback); room kept in --config-dir\n\
  --owner-token-file file holding the owner token for creating the room (with --relay); or env VQ_RELAY_OWNER_TOKEN.\n\
                (--owner-token TOKEN also works but is visible in `ps`)\n\
  --log-dir     log directory for this run (default: configured, else ~/Documents/Ventriloquist)\n\
  --config-dir  identity / pairing / config directory\n\
                (default: <OS local config dir>/com.ventriloquist.desktop.dev, never the app's)\n\
  --name        display name for this run (default: configured, else host name)\n\
  env VQ_LOG=1  diagnostics on stderr";

struct Args {
    connect: String,
    relay: Option<String>,
    owner_token: Option<String>,
    owner_token_file: Option<PathBuf>,
    log_dir: Option<PathBuf>,
    config_dir: Option<PathBuf>,
    name: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    parse_args_from(std::env::args().skip(1))
}

fn parse_args_from(args: impl IntoIterator<Item = String>) -> Result<Args, String> {
    let mut a = Args {
        connect: format!("127.0.0.1:{}", vq_protocol::TCP_DEFAULT_PORT),
        relay: None,
        owner_token: None,
        owner_token_file: None,
        log_dir: None,
        config_dir: None,
        name: None,
    };
    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--connect" => a.connect = value()?,
            "--relay" => a.relay = Some(value()?),
            "--owner-token" => a.owner_token = Some(value()?),
            "--owner-token-file" => a.owner_token_file = Some(PathBuf::from(value()?)),
            "--log-dir" => a.log_dir = Some(PathBuf::from(value()?)),
            "--config-dir" => a.config_dir = Some(PathBuf::from(value()?)),
            "--name" => a.name = Some(value()?),
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if (a.owner_token.is_some() || a.owner_token_file.is_some()) && a.relay.is_none() {
        return Err("--owner-token and --owner-token-file need --relay".to_owned());
    }
    if a.owner_token.is_some() && a.owner_token_file.is_some() {
        return Err("use only one of --owner-token and --owner-token-file".to_owned());
    }
    Ok(a)
}

/// The owner token: the file, else `--owner-token`, else `VQ_RELAY_OWNER_TOKEN`.
fn owner_token(flag: &Option<String>, file: Option<&std::path::Path>) -> Result<Option<String>, String> {
    if let Some(f) = file {
        let t = std::fs::read_to_string(f).map_err(|e| format!("cannot read {}: {e}", f.display()))?;
        return Ok(Some(t.trim().to_owned()).filter(|t| !t.is_empty()));
    }
    if flag.is_some() {
        return Ok(flag.clone());
    }
    Ok(std::env::var("VQ_RELAY_OWNER_TOKEN").ok().filter(|t| !t.is_empty()))
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
    let config_dir = args.config_dir.unwrap_or_else(default_dev_config_dir);
    let (transport, relay): (Box<dyn Transport>, _) = match &args.relay {
        None => (Box::new(TcpTransport::new(args.connect)), None),
        Some(url) => {
            let setup = std::fs::create_dir_all(&config_dir)
                .and_then(|()| RelayRoomStore::load_or_create(&config_dir))
                .and_then(|store| store.set_url(url).map(|()| Arc::new(store)));
            let store = match setup {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("vq-host: cannot set up the relay room: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let owner_token = match owner_token(&args.owner_token, args.owner_token_file.as_deref()) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("vq-host: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let opts = RelayOptions { owner_token, ..RelayOptions::default() };
            let (t, _relay_handle) = RelayTransport::new(store.clone(), opts);
            (Box::new(t), Some(store))
        }
    };
    let opts = CoreOptions {
        config_dir,
        log_dir_override: args.log_dir,
        name_override: args.name,
        clock: Arc::new(SystemClock::new()),
        relay,
    };
    let (handle, mut events, task) =
        match spawn_host(opts, transport) {
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
    // Exit now: a blocking read of stdin (an open pipe or FIFO) would
    // otherwise keep the runtime from shutting down.
    std::process::exit(0)
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

#[cfg(test)]
mod tests {
    use super::parse_args_from;

    fn parse(a: &[&str]) -> Result<super::Args, String> {
        parse_args_from(a.iter().map(|s| (*s).to_owned()))
    }

    #[test]
    fn relay_flags() {
        let a = parse(&["--relay", "http://127.0.0.1:1", "--owner-token", "t"]).unwrap();
        assert_eq!(a.relay.as_deref(), Some("http://127.0.0.1:1"));
        assert_eq!(a.owner_token.as_deref(), Some("t"));
        assert!(parse(&["--owner-token", "t"]).is_err());
        let b = parse(&["--relay", "http://127.0.0.1:1", "--owner-token-file", "/x"]).unwrap();
        assert_eq!(b.owner_token_file.as_deref(), Some(std::path::Path::new("/x")));
        assert!(parse(&["--relay", "u", "--owner-token", "t", "--owner-token-file", "/x"]).is_err());
        assert!(parse(&["--relay"]).is_err());
        assert!(parse(&["--connect", "x:1"]).unwrap().relay.is_none());
    }
}
