use std::path::PathBuf;

use vq_relay::{serve, Config};

fn usage() -> ! {
    eprintln!(
        "usage: vq-relay [--listen ADDR] [--data-dir DIR] [--owner-token-file FILE]\n\
         \n\
         Owner token: VQ_RELAY_OWNER_TOKEN, or --owner-token-file (a 0600 file).\n\
         Defaults: --listen 127.0.0.1:8787, --data-dir ~/Library/Application Support/vq-relay"
    );
    std::process::exit(2)
}

fn default_data_dir() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/vq-relay")
    } else {
        home.join(".local/share/vq-relay")
    }
}

#[tokio::main]
async fn main() {
    let mut listen = "127.0.0.1:8787".to_owned();
    let mut data_dir = default_data_dir();
    let mut token_file: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--listen" => listen = args.next().unwrap_or_else(|| usage()),
            "--data-dir" => data_dir = args.next().unwrap_or_else(|| usage()).into(),
            "--owner-token-file" => token_file = Some(args.next().unwrap_or_else(|| usage()).into()),
            _ => usage(),
        }
    }
    let token = match (std::env::var("VQ_RELAY_OWNER_TOKEN").ok(), token_file) {
        (Some(t), _) if !t.trim().is_empty() => t.trim().to_owned(),
        (_, Some(f)) => match std::fs::read_to_string(&f) {
            Ok(t) if !t.trim().is_empty() => t.trim().to_owned(),
            Ok(_) => fatal(&format!("owner token file {} is empty", f.display())),
            Err(e) => fatal(&format!("cannot read owner token file {}: {e}", f.display())),
        },
        _ => fatal("no owner token: set VQ_RELAY_OWNER_TOKEN or pass --owner-token-file"),
    };
    let listener = match tokio::net::TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => fatal(&format!("cannot listen on {listen}: {e}")),
    };
    eprintln!("vq-relay listening on {listen}, data dir {}", data_dir.display());
    if let Err(e) = serve(listener, Config::new(token, data_dir)).await {
        fatal(&format!("server error: {e}"));
    }
}

fn fatal(msg: &str) -> ! {
    eprintln!("vq-relay: {msg}");
    std::process::exit(1)
}
