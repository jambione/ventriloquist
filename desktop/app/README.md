# Ventriloquist desktop app (Tauri v2)

```sh
cd desktop/app
npm ci
npm test            # vitest (reducer, formatters, adversary suite)
cargo tauri build   # bundle: target/release/bundle/macos/Ventriloquist.app
```

## Running

- macOS: launch the bundle with `open target/release/bundle/macos/Ventriloquist.app` (or from Finder). Bluetooth is gone (SPEC_V3), so there is no TCC restriction on running the binary from a terminal any more; the app only makes outbound HTTPS/WebSocket connections to the relay.
- Only one instance runs: a second launch focuses the first window (`tauri-plugin-single-instance`), and the core also locks `<config dir>/.lock`.
- **Always-on log file** (all OSes): `<config dir>/logs/ventriloquist.log`, rotated at 2 MB, 3 files kept (`.1`, `.2`). Windows: `%LOCALAPPDATA%\com.ventriloquist.desktop\logs\ventriloquist.log`; macOS: `~/Library/Application Support/com.ventriloquist.desktop/logs/ventriloquist.log`. Info level; the app version and OS version are logged at start-up, plus every relay connection attempt (relay URL and proxy choice, never a secret), WebSocket/fallback switch and error. Settings → Diagnostics shows the path and opens the file or folder.
- `VQ_LOG=1` switches this log to Debug for this app and the core (Info for dependencies) and also prints it on stderr.

## Notes

- The log line `web content process terminated` at start-up comes from tauri-runtime-wry (it is logged unconditionally while a webview is built) and is harmless. A real WebContent crash reloads the page, which asks for a snapshot again (including the log-warning state).
- The web view receives no path from the user's side: the folder picker runs in Rust and sends the chosen folder to the host; `open_log_folder` opens only the folder the host reports. See docs/SPEC_QUESTIONS.md, W7.
- **Settings → Relay** (SPEC_V3 §6): relay URL (default `https://relay.jbrasfield.com`), owner token (password field), link status with a categorised reason and a hint, **Test connection** (health, room creation, WebSocket; opening the WebSocket joins the room briefly as a phone) and **Reset relay room** (two-click confirm; new room id and secret, so every phone is un-paired; the app also forgets the paired phones, and the old room is deleted on the relay if possible).
- **Owner token storage.** The token is kept in the OS secret store through the `keyring` crate (macOS Keychain, Windows Credential Manager; service `com.ventriloquist.desktop`, user `relay-owner-token`). If that store is unavailable or refuses, a file `owner_token` with mode 0600 in the config directory is used (Windows: per-user `%LOCALAPPDATA%`), and Settings says which one holds it. The web view never receives the token. "Generate token" makes a new one (32 random bytes, base64), stores it and shows it once, for the relay's owner-token setting.
- **Settings → Phones** (SPEC_V3 §5): **Add phone** opens a dialog with the pairing QR (rendered locally by the `qrcode` crate as an SVG `data:` URL, command `qr_svg`; no network fetch) and a countdown. A new QR replaces it every 120 s. It opens by itself once per run while no phone is paired. The paired phones list has Forget (two-click). A pairing by QR shows "Phone “name” paired." and closes the dialog.
- **Toolbar** (`connectionStatus`): `Relay unreachable — <reason>` (DNS lookup failed, proxy needs credentials, proxy blocked, certificate not trusted, owner token rejected, room conflict, connection failed); `Connecting to the relay…`; `Connected via relay (WebSocket|fallback) · Waiting for iPhone`; with a phone: `Connected to <name> (secure)` (plus ` · relay fallback` on the long-poll fallback), `Pairing with …`, `Connecting to …`.
