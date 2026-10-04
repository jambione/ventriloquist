# Ventriloquist desktop app (Tauri v2)

```sh
cd desktop/app
npm ci
npm test            # vitest (reducer, formatters, adversary suite)
cargo tauri build   # bundle: target/release/bundle/macos/Ventriloquist.app
```

## Running

- **macOS: launch the bundle with `open target/release/bundle/macos/Ventriloquist.app` (or from Finder).** Do not run `Contents/MacOS/Ventriloquist` from a terminal: macOS attributes Bluetooth use to the responsible process (the terminal), which has no usage description, and aborts the app (TCC). `cargo tauri dev` can hit the same abort; grant Bluetooth to the terminal app, or test the bundle (`cargo tauri build --debug`).
- Only one instance runs: a second launch focuses the first window (`tauri-plugin-single-instance`), and the core also locks `<config dir>/.lock`.
- `VQ_LOG=1` prints diagnostics on stderr (Debug for this app and the core, Info for dependencies).

## Notes

- The log line `web content process terminated` at start-up comes from tauri-runtime-wry (it is logged unconditionally while a webview is built) and is harmless. A real WebContent crash reloads the page, which asks for a snapshot again (including the log-warning state).
- The web view receives no path from the user's side: the folder picker runs in Rust and sends the chosen folder to the host; `open_log_folder` opens only the folder the host reports. See docs/SPEC_QUESTIONS.md, W7.
