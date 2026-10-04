# Ventriloquist — Manual On-Device Test Checklist

Owner's verification checklist for iPhone app + desktop app over Bluetooth LE. Run on every release before personal use.

---

## Setup

### iOS
1. `cd ios/App && xcodegen`
2. Open `Ventriloquist.xcodeproj` in Xcode
3. Select your iPhone, then **Product** → **Run** (automatic signing, team D5K4MV7298)

### macOS Desktop
1. `cd desktop/app && npm ci && cargo tauri build`
2. `open target/release/bundle/macos/Ventriloquist.app` from repo root
   - Never run the raw binary from Terminal (macOS privacy check aborts it)
   - `cargo tauri dev` may also be aborted by the same privacy check; if so, test with the bundled app via `open`

### Windows Desktop
- Build on Windows PC with Rust MSVC + WebView2: `cargo tauri build`
- Choose webviewInstallMode (embedBootstrapper recommended for offline install)

---

## First Run & Permissions

- [ ] **Speech & microphone** — start recording → speech permission prompt → allow → no crash
- [ ] **Bluetooth permission** — app requests → allow → can connect to desktop
- [ ] **Device name** — iPhone name visible to desktop in Host list

---

## Pairing

- [ ] **Pair with code** — desktop shows 6-digit code, countdown visible, phone enters code, enters history
- [ ] **Wrong code ×3** — first 2 failures show error on phone; 3rd invalidates code → must start over
- [ ] **Code expiry** — wait 120 s without entering → code expires, must pair again
- [ ] **Forget host** — swipe on paired desktop in Host picker → host removed from list
- [ ] **Re-pair** — forget, then pair again with same desktop → new code works
- [ ] **Spoofed HELLO** — connect nRF Connect with fake Ventriloquist UUID → doesn't disconnect real desktop

---

## Live Dictation & Streaming

- [ ] **Partial text live** — start recording → speak words → partial (secondary color) appears on desktop in real time
- [ ] **Final on stop** — stop recording → final text (primary color) locks in on desktop
- [ ] **Throttling** — rapid partial updates arrive at ≤5/sec, never drop intermediate text
- [ ] **Partial streaming off** — disable in iPhone Settings → only final/edit sent to desktop
- [ ] **Streaming with 2 desktops** — pair with 2 Macs → both receive utterances; active host listed on phone

---

## Edits & History

- [ ] **Edit after stop** — stop recording → desktop shows editable transcript → modify text → "Send correction" → desktop updates
- [ ] **Edit not sent if unchanged** — stop → don't modify → "Send correction" disabled
- [ ] **Re-send from history** — tap entry in History → Re-send → new entry sent as new `id` to active desktop
- [ ] **History Clear all** — tap Clear all → confirm → all entries deleted, list updates immediately
- [ ] **History persists** — close app → reopen → past 1,000 entries still there (capped, oldest pruned)
- [ ] **Delivery status** — History shows ✓ (acked), ⏳ (pending), or ✗ (failed)

---

## Two Desktops

- [ ] **Pick active host** — Host picker shows paired + nearby unpaired → tap one → marked active
- [ ] **Last host remembered** — close app, reopen → previous host auto-selected when it connects
- [ ] **Auto-reconnect** — close desktop app → phone shows "Not connected — will send when connected" → open desktop → phone reconnects, backfill utterances

---

## Robustness

### Bluetooth State
- [ ] **Bluetooth off/on** — toggle system Bluetooth off mid-session → service stops → toggle on → service re-advertised, desktops reconnect, no duplicate entries

### Range & Connection
- [ ] **Walk out of range** — active recording → leave range → final sends when in range again
- [ ] **Return in range** — out of Bluetooth range → walk back → service re-added, desktop reconnects within 15 s

### App State
- [ ] **Background during recording** — start recording → background app → app stops recording, sends final → foreground → can start again
- [ ] **Background during model download** — first run, model downloading → background → return → download resumes, mic still accessible
- [ ] **Phone call/Siri mid-recording** — start recording → phone call/Siri interrupts → recording stops, final sent
- [ ] **AirPods during recording** — start with wired headset → connect/disconnect AirPods mid-speech → final arrives intact

### Scale & Duration
- [ ] **32,000-byte utterance** — continuous dictation reaching 32 KB → throttles at framing layer, no loss/reorder, queue resumes
- [ ] **5-minute continuous** — record 5 min continuously → memory stable, text converter/analyzer don't crash, final text complete

### Custom Vocabulary
- [ ] **Custom terms** — Settings → add "kubectl" → start recording, say it → recognized and spelled correctly

---

## Desktop App

- [ ] **Copy button** — click Copy on any entry → "Copied ✓" shows 1.5 s, exact text in clipboard (no trailing newline)
- [ ] **Search** — type substring in search field → entries filtered, case-insensitive
- [ ] **Clear view** — click Clear view → on-screen list empties, log files untouched
- [ ] **Transcript list** — newest at bottom, auto-scrolls only when already at bottom, monospace font, selectable text
- [ ] **Partial entry** — while recording, entry shows dimmed + italic + "speaking…", becomes normal on final
- [ ] **Edited badge** — if entry edited after sending, shows "edited" badge
- [ ] **Settings** — open Settings → change device name + log directory → changes persist on reopen
- [ ] **Log file contents** — stop recording → open log file `~/Documents/Ventriloquist/YYYY-MM-DD.md` → entry present with time, device name, text indented

---

## Single Instance

- [ ] **macOS: open -n** — `open -n Ventriloquist.app` → second window shows error, first window stays active
- [ ] **Windows: double-click** — double-click installer or app icon → second launch focuses existing window
- [ ] **Daemon disconnection** — confirm only one host connects to phone as BLE central, not two

---

## Desktop Platform-Specific

### macOS
- [ ] **Dock & Cmd+Q** — close via Cmd+Q / red button / Dock menu → RunEvent::Exit fires → last final logged, phone disconnects within ~8 s
- [ ] **Log folder not .app** — folder picker rejects `.app` packages (NSOpenPanel handling)
- [ ] **WebContent crash** — kill `com.apple.WebKit.WebContent` → page reloads, entries preserved, log banner persists

### Windows
- [ ] **WebView2 install** — first run with embedBootstrapper → WebView2 installs if missing, app runs
- [ ] **Bluetooth off/unauthorized** — toggle Bluetooth off → toolbar shows "Bluetooth off" message
- [ ] **Open log folder** — Settings → Open log folder → opens Explorer at log directory
- [ ] **Long writes to RX** — monitor via Bluetooth sniffer: RX writes never have non-zero offset (not fragmented)

---

## Security Spot Checks

MAC verification, replay protection, encryption and plaintext rejection are covered by the automated suites (`scripts/verify.sh`), so they are not manual checks.

- [ ] **Keychain identity after reinstall** — delete the iOS app → reinstall → open the Host picker → expected: desktops appear under "Nearby, not paired" (the app's paired-host list was deleted with the app, though the Keychain identity survives); pairing again with a new code succeeds and the desktop replaces its old record for this phone without needing Forget on the desktop.

---

## Notes

- All checkboxes must pass before release. If any fail, file findings with file/line references and halt.
- Device-specific items (D1–D6 Windows) skip if testing on macOS only; note which platform(s) verified.
- Log at least one full session: pair, record multi-part utterance, edit, history re-send, copy to clipboard.
