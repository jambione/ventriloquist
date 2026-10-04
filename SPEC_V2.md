# Ventriloquist — Specification v2: Bindings

Status: **APPROVED by owner 2026-10-04**, from the owner interview. **Revised the same day: Windows is the primary platform** (§4.8). This is a delta on [SPEC.md](SPEC.md) (v1). Everything in v1 still applies unless this document changes it.

**Summary.** The desktop app can *bind* up to 9 target text boxes in other apps (Teams chat, Copilot chat, a terminal running the Claude CLI, …) to numbered **slots**. One slot is *active*. When a new final utterance arrives, the desktop inserts it into the active slot's target, then returns focus to wherever the user was. Global hotkeys select slots and create bindings.

---

## 1. Goals and non-goals

### Goals
- B-G1. Bind the focused text box of any app to slot 1–9 with a global hotkey, and select the active slot with another global hotkey.
- B-G2. Deliver each **new final** utterance to the active slot's target. Use the best insertion method for each target and never lose the user's focus or clipboard.
- B-G3. Make target apps' "Enter = send" behaviour safe: line breaks are soft (Shift+Enter), and pressing Enter at the end is an opt-in per slot.
- B-G4. Make it visible where every utterance went (or why it didn't go).

### Non-goals (v2)
- No phone or protocol changes. The iPhone app is unchanged, and the protocol stays at `v: 1`.
- No live/partial typing, and no re-typing of corrections. An `edit` updates the Ventriloquist entry only.
- No on-screen toast or menu bar item. Feedback is sounds plus the Ventriloquist window.

## 2. Owner decisions (v2 interview)

| Topic | Decision |
|---|---|
| Typical targets | Teams chat, Copilot chat (web/Electron), terminal running Claude CLI, plus native text fields |
| Insertion method | **Auto**: Accessibility insertion where the target supports it, otherwise activate the window and type keystrokes (§4.3) |
| When | **Finals only.** Edits are never re-typed |
| Platforms | **Windows (primary) and macOS** (§4.8 for Windows specifics) |
| Create binding | Hotkey while the target field is focused: **Ctrl+Option+Shift+1…9** (macOS) / **Ctrl+Shift+Alt+1…9** (Windows) |
| Select slot | **Ctrl+Shift+1…9** selects slot N. **Ctrl+Shift+0** = Off (display only) |
| Submit (Enter) | Per-slot **auto-submit** switch, **default off** |
| Line breaks | Per-slot **newline mode**: `shift_enter` (soft newline) or `spaces` (flatten to one line). Default `shift_enter` for chat/browser/editor targets, **`spaces` for terminal targets**, because Shift+Enter can arrive as Enter (submit) in some terminals |
| Focus | **Return to where the user was** after inserting |
| Persistence | **Best-effort re-match** after restarts; otherwise the slot shows "unbound" |
| Target missing | **Display only + warning**. Never fall back to another window |
| Elevated target (Windows) | **Refuse** with "⚠ target is elevated" (UIPI) |
| Windows verification | Local `cargo check --target x86_64-pc-windows-msvc`; Windows CI unit tests and installer build; Windows CI integration test (Notepad); owner's Windows manual checklist |
| Active-slot display | **Ventriloquist window** slot bar (no toast, no menu bar) |
| Hotkey feedback | **Brief sound**: one for selected, another for empty slot or Off |
| Long text | **Type up to 200 characters; paste above that**, restoring the previous clipboard |
| Hotkeys | Fixed defaults, **modifiers editable in Settings**, with conflict detection |
| Transcript extras | Per-entry **delivery badge** and a **"Send to active slot"** button |

## 3. Architecture

```
vq-host-core (v1) ──► HostEvent::FinalAccepted{entry}  ──► DeliveryManager (desktop/app, Rust)
                                                             │  active slot, settings, serial queue
global hotkeys (tauri-plugin-global-shortcut) ──► SlotCommands ┤
                                                             ▼
                                                   vq-inject (new crate)
                                                   ├─ model: Slot, BindingTarget, SlotSettings
                                                   ├─ store: bindings.json + re-match (pure)
                                                   ├─ planner: plan_delivery(caps, text, settings) -> Vec<Action>  (pure)
                                                   └─ Injector trait
                                                        ├─ WindowsInjector (UIA + SendInput + Win32 clipboard + foreground mgmt)
                                                        ├─ MacInjector (AX + CGEvent + NSPasteboard + NSWorkspace)
                                                        └─ UnsupportedInjector (other OSes)
```

- **New crate `desktop/inject` (`vq-inject`)**, part of the workspace.
  - The model, the store/re-match logic and the **delivery planner are pure Rust**, OS-independent and fully unit-tested.
  - The executors live behind `cfg(target_os = "windows")` and `cfg(target_os = "macos")`; any other OS gets `UnsupportedInjector`. `BindingTarget.app_id` holds the bundle id on macOS and the executable name on Windows.
  - Use maintained bindings (`objc2`, `objc2-app-kit`, `objc2-application-services` / `accessibility-sys`, `core-graphics`) and keep `unsafe` minimal, documented and in one module.
- **Core change (additive):** `HostEvent::FinalAccepted { entry }`.
  - It is emitted exactly when the logger would log a final: the first acceptance of a `final` for an `id`. It is never emitted for duplicates, stale revisions, partials, edits, or re-deliveries after a restart that the log index already holds.
  - This is the **only** trigger for automatic delivery, so a utterance is never typed twice.
- **DeliveryManager** (in the Tauri crate, or a small `desktop/app/src-tauri/src/delivery.rs` module):
  - Owns the active slot and processes deliveries **serially**, one at a time, on a dedicated thread, because AX and CGEvent calls are blocking.
  - Emits `delivery` events to the UI. It never blocks the host event loop.
- **Hotkeys:** `tauri-plugin-global-shortcut`. Registration failures (combination taken) are reported to the UI.
- **No protocol changes.**

## 4. Behaviour

### 4.1 Creating a binding (Ctrl+Option+Shift+N)
1. Read the frontmost application (pid, bundle id, name) and, through Accessibility, its focused window (`AXFocusedWindow`: title) and focused element (`AXFocusedUIElement`: role, subrole, whether `AXValue`/`AXSelectedText` is settable).
2. **Refuse** when:
   - the frontmost app is Ventriloquist itself;
   - the element is a secure text field (`AXSecureTextField` subrole);
   - Accessibility permission is missing (§4.7).

   Play the "error" sound and show a notice.
3. Store slot N = `{bundle_id, app_name, window_title, element_role, element_subrole, ax_insertable: bool}` plus the live AX references (window and element) for this session. Binding a slot replaces whatever it held before.
4. Binding **also makes slot N active** (O1), and plays the "selected" sound.

### 4.2 Selecting the active slot (Ctrl+Shift+N / Ctrl+Shift+0)
- **Ctrl+Shift+N** with N bound: N becomes active and the "selected" sound plays (`NSSound` "Tink").
- **Ctrl+Shift+N** with N empty: the active slot is unchanged and the "empty" sound plays ("Basso").
- **Ctrl+Shift+0:** Off (no delivery); play "Pop".
- The active slot is persisted (in `bindings.json`) and restored on start if that slot re-matched (§4.6); otherwise Off.

### 4.3 Delivery of a final
On `FinalAccepted`, when the active slot ≠ Off:
1. **Resolve the target.** Use the live AX window reference if it is still valid. If not, re-match (§4.6). If nothing matches, the result is **`missing`**: show a notice ("Slot 2 (Microsoft Teams) not found — not sent"), set the badge to ✗, and stop. **Never fall back** to the frontmost app or any other window.
   - **Title check.** A slot whose **`follow_title_changes`** is **false** (the default for every app except terminals) is delivered to only while the window's live title equals the bound title exactly; otherwise the result is **`blocked("window changed: was '<old>', now '<new>'")`** and nothing is typed. This stops text going into another chat or tab that was opened in the same window. Rebinding updates the bound title. Slots with it **true** (terminals, whose titles change with every command) adopt the new title and keep delivering.
2. **Refuse** (result **`blocked`**) when:
   - the target element is a secure text field;
   - secure event input is enabled system-wide (`IsSecureEventInputEnabled()`, e.g. a password prompt is up);
   - after activation, the element that actually has focus is re-checked (a secure text field, or on Windows an element that cannot be shown *not* to be a password, §4.8) — the bound element may no longer be the focused one.
   Every refusal is logged (`VQ_LOG`) with its reason and shown as a notice.
3. **Plan** with the pure planner `plan_delivery(caps, text, settings)`, where caps = {ax_insertable, app category}:
   - **AX path:** only if the element is a native text field/area whose `AXSelectedText` is settable, and the app is not on the keystroke-preferred list (browsers, Electron apps incl. Teams/VS Code/Slack, terminals: Terminal, iTerm2, Warp, Ghostty, WezTerm, Alacritty, kitty). Set `AXSelectedText` to the text, inserting at the cursor and replacing any selection. If text has line breaks, insert them as `\n` — AX insertion doesn't trigger send. **No activation needed.** Read the value back to confirm; if that fails, fall through to the keystroke path.
   - **Keystroke path:**
     1. Remember the current frontmost app.
     2. Activate the target app and raise the bound window (`AXRaise`, `NSRunningApplication.activate`).
     3. Re-focus the bound element (`AXFocused = true`) if it is still valid.
     4. Wait until the target is frontmost (poll ≤ 500 ms; else result `failed`).
     5. Insert the text:
        - **Single-line text ≤ 200 characters, or multi-line text ≤ 1,000 characters:** type it as Unicode keyboard events (`CGEventKeyboardSetUnicodeString`, chunks of ≤ 20 UTF-16 units). Each line break is **Shift+Return**. A tab is typed as a **space** (a real Tab key would move keyboard focus or complete in a shell).
        - **Longer text:** **paste**, line by line (tabs stay in pasted text):
          1. Snapshot every pasteboard item and type (if any type yields no data, the clipboard is not restorable: type instead).
          2. Set the line's text and press Cmd+V, wait 150 ms and check that nobody else wrote to the clipboard, pressing Shift+Return between lines.
          3. Restore the snapshot no earlier than **400 ms** after the last paste (the target reads the clipboard asynchronously).
          4. If the user changed the clipboard in between (`changeCount` differs from the one we set), do **not** restore.
     6. If the slot's **auto-submit** is on: wait 150 ms for the text to be consumed, re-verify that the target is still the frontmost window, then press Return. If the focus changed, Return is **not** sent and the result is `failed("focus changed before submit")`.
     7. Wait 150 ms, then re-activate the remembered app (unless it *was* the target).

     **User input guard.** Before a delivery that sends keystrokes, wait until the user has been idle for 300 ms (at most 3 s, then proceed). During the delivery, physical (non-injected) key presses or mouse clicks stop it at once: no further text, **never** the auto-submit Return, result `failed("interrupted by user input")`. (Windows: low-level keyboard/mouse hooks that look at the injected flag; macOS: the hardware-event idle time sampled between chunks.) The clipboard restore and re-activation still run.
4. Text is the entry's final text **exactly**: no trimming, no added prefix or suffix. Control characters other than `\n`/`\t` are dropped from typing (logged). `\r\n`, a lone `\r`, U+2028, U+2029 and U+0085 are each one line break. For terminal slots bidirectional control characters are dropped too (they can make a command line display differently from what runs).
5. **Result** `sent` / `missing` / `blocked` / `failed(reason)` is shown as a badge on the entry (§4.5) and logged to stderr when `VQ_LOG=1`. It is **not** written to the Markdown log, whose format is unchanged.

### 4.4 Ordering and races
- Deliveries are serial and FIFO. A second final arriving during a delivery waits.
- Keyboard events are posted only after the target is confirmed frontmost. If the frontmost app changes during typing (the user clicked elsewhere), stop and report `failed("focus changed")`. Text already typed stays.
- Slot hotkeys pressed during a delivery take effect for the next delivery.

### 4.5 Desktop UI additions (Ventriloquist window)
- **Current-dictation view (owner decision 2026-10-04):** by default the main area shows only the newest utterance (SPEC §6.1) in large monospace text, with live partials, the device name and time, the delivery badge, **Copy** and **Send to active slot**. A toolbar **History** toggle (persisted in `localStorage`) switches to the full list. Everything below (badge, Send to active slot) applies to the entry in either view.
- **Slot bar** under the toolbar:
  - chips **Off · 1 … 9**. Each bound chip shows `N · App — window title` (truncated, full text in a tooltip).
  - Unbound chips are dimmed; the active chip is highlighted. Click a chip to select it, the same as the hotkey.
  - Each bound chip has a ⋯ menu: **Auto-submit (Enter)** toggle, **Follow window when its title changes** toggle (§4.3; default on for terminals, off otherwise), **✕ Clear** (clears that binding; if it was the active slot, the active slot becomes Off).
  - The bar is one wrapping row of chips at any window width ≥ 320 px.
  - Re-matched-but-unverified chips show a small "?" until the first successful delivery.
- **Entry badge:** `→ 2 · Teams ✓`, `not sent (Off)`, `✗ slot 2 missing`, `⚠ blocked (secure input)`, `✗ failed: <reason>`, or `sending…`.
- **"Send to active slot"** button per entry (next to Copy): delivers that entry's **current** text, including corrections, to the active slot with the same rules. It is disabled when Off.
- **Settings → Bindings:**
  - **Accessibility permission:** status, with an "Open System Settings" button.
  - **Hotkey modifiers**, two pickers:
    - select: default Ctrl+Shift;
    - bind: default Ctrl+Option+Shift.
    - Digits stay 0–9. If a combination fails to register, it is shown as "taken by another app".
  - The list of slots, each with **Clear binding**.
  - **Clear all bindings** (two-click confirm, like Forget): clears every slot and sets the active slot to Off (backend command `clear_all_slots`).
- Each bound chip's ⋯ menu also has the **Newline mode** choice (`Shift+Enter` / `Spaces`).

### 4.6 Persistence and re-match
- `bindings.json` lives in the config dir: an atomic write, version field, slots 1–9, and the active slot. Each slot has `follow_title_changes`; a missing key gets the per-app default on load, and so does a missing `newline_mode`. One invalid slot record is skipped with a warning; it does not discard the rest. A file of another version is left untouched (never renamed, never overwritten until the user binds a slot); a corrupt file is moved to a fresh `bindings.json.corrupt[.N]`.
- **Re-match**, on start and when a live reference is invalid:
  1. Find running apps with the bundle id.
  2. Look for a window whose title equals the saved title exactly (app ids compare case-insensitively, Unicode-aware). Several matches: **unbound**, never guess. Windows on other virtual desktops count here.
  3. If none, and the app has exactly **one** standard window, use it and update the saved title (only for slots that follow title changes; others are then blocked at delivery by the title check). Not used for browsers, `ApplicationFrameHost.exe` or generic runtimes (`javaw`, `python`, `node`, `electron`...), which match by exact title only. On Windows the window's class (and AppUserModelID when the app is packaged) must equal the saved ones, and a window on another virtual desktop is never chosen by this fallback.
  4. Otherwise mark the slot **unbound**: keep the saved description, dimmed, with "rebind" shown.
- The re-matched element is the window's focused element at delivery time, if its role matches the saved role; otherwise the keystroke path types into the window's focused element after activation.
- Re-matched slots are shown with "?" until a delivery succeeds.

### 4.7 Permissions
- **macOS Accessibility** is required: `AXIsProcessTrustedWithOptions`, prompting on first bind attempt. Global hotkeys via the plugin don't need it.
- Without Accessibility:
  - binding and delivery fail with a notice that links to Settings;
  - the slot bar shows "Accessibility permission needed".
- The Info.plist gains nothing new; Accessibility has no usage string.
- **Note:** an unsigned app rebuilt from source may need re-granting after each rebuild, because macOS keys the grant to the code signature. Document this in README and MANUAL_TEST.

### 4.8 Windows specifics
- **Capture:**
  - `GetForegroundWindow` gives the HWND; from it, get the pid and the exe name (`QueryFullProcessImageNameW`) and the window title (`GetWindowTextW`).
  - UI Automation `GetFocusedElement` gives ControlType, ClassName, `IsPassword` and RuntimeId. The element may belong to another process than the window (WebView2 in new Teams/Outlook, UWP apps under `ApplicationFrameHost`, conhost): it is used regardless of its pid. If UIA reports none, the slot binds at window level.
  - Refuse password elements, and refuse Ventriloquist's own windows.
  - The window's class name and (packaged apps) AppUserModelID are stored for the re-match (§4.6).
- **Insertion path:** **always the keystroke/paste path** in v2. UIA has no reliable insert-at-cursor, and `ValuePattern.SetValue` replaces the whole field. Direct insertion is deferred.
- **Elevation (UIPI):** if the target process's integrity level is higher than ours, or its token can't be opened, the result is `Blocked("target is elevated")`. Check this before activating.
- **Activation:**
  1. Remember the foreground HWND.
  2. Bring the target forward with `SetForegroundWindow`. Windows' foreground-lock rules need the documented `AttachThreadInput` technique around it: attach to the current foreground thread, call `BringWindowToTop` + `SetForegroundWindow`, then detach. Restore minimized windows with `ShowWindow(SW_RESTORE)` first.
  3. Verify with `GetForegroundWindow() == target` (poll ≤ 500 ms), else `Failed("could not focus target")`.
  4. Re-focus the saved UIA element (`SetFocus`) if its RuntimeId still resolves.
  5. **Fail-closed password check:** whatever UIA reports as focused now must be known not to be a password field; if there is no focused element or `IsPassword` cannot be read, the result is `Blocked("cannot verify field is not a password")`. The focused element's RuntimeId is re-checked before every chunk.
- **Typing:** `SendInput` with `KEYEVENTF_UNICODE` per UTF-16 unit, sent in batches. Tabs are typed as spaces (§4.3). Held modifier keys are waited out before input; if `SendInput` inserts only part of a modifier sequence, the modifiers are released again. Shift+Enter is VK_SHIFT+VK_RETURN, and auto-submit is VK_RETURN. Abort with `Failed("focus changed")` if the foreground window changes mid-typing.
- **Paste (> 200 characters):**
  1. Snapshot the clipboard: every format whose data is an HGLOBAL. If the clipboard holds formats that can't be snapshotted (GDI handles such as `CF_BITMAP`, or delayed rendering), **type instead of paste**, so we never lose the user's clipboard.
  2. Set `CF_UNICODETEXT` and press Ctrl+V.
  3. Restore no earlier than 400 ms after the last paste, only if `GetClipboardSequenceNumber` still equals the value right after our set (read while the clipboard is still open). The restore adds the history/cloud exclusion markers. Private formats 0x200–0x2FF and clipboards owned by processes that render lazily (Excel, Office, Remote Desktop) count as not restorable: type instead. The clipboard-owner window lives on its own thread with a message loop.
- **Sounds:** `PlaySoundW` with the system aliases `SystemAsterisk` (selected), `SystemHand` (empty/error) and `SystemExclamation` (Off), using `SND_ALIAS | SND_ASYNC`.
- **Runtime identity and re-match:**
  - At runtime, a binding is valid while `IsWindow(hwnd)` holds and the pid is unchanged.
  - Re-match on (exe name, exact title), then fall back to that exe's single visible top-level window, else unbound.
- **Hotkeys:** `tauri-plugin-global-shortcut` (RegisterHotKey). Defaults:
  - select: **Ctrl+Shift+0–9**;
  - bind: **Ctrl+Shift+Alt+1–9**.

  Conflicts are shown as "taken". Note: some Windows input-language settings claim Ctrl+Shift+0, so the conflict UI must handle that.
- **No Accessibility permission prompt** on Windows; the macOS-only permission UI is hidden.

## 5. Security and safety
- Text is only ever injected into the **bound** target, never the frontmost app by fallback.
- Secure text fields and secure event input are never typed into (§4.3).
- Delivery is triggered only by `FinalAccepted` (authenticated, first-acceptance finals) or by the user's explicit "Send to active slot" click.
- Clipboard contents are restored, and never logged.
- Auto-submit is off by default for every slot.
- **Spec-level risk, accepted by the owner's choice of auto-submit per slot:** with auto-submit on for a terminal slot, dictated text is executed by the shell or Claude CLI. The slot chip shows a "⏎" marker when auto-submit is on.

## 6. Verification (v2 gates, added to scripts/verify.sh)
0. **Windows compile check on this Mac:** `cargo check -p vq-inject --target x86_64-pc-windows-msvc` (and the Tauri crate if its dependencies allow cross-checking).
1. `cargo test -p vq-inject`: planner (every path, line breaks, the 200-character threshold, auto-submit, control characters, CRLF), store/re-match (exact title, single window, ambiguous → unbound, corrupt file → defaults + warning), slot selection logic.
2. `cargo test -p vq-host-core --features dev-tcp`: `FinalAccepted` fires exactly once per id across duplicates, stale revisions, edits and restart re-delivery.
3. DeliveryManager tests with a **fake Injector**: serial FIFO, Off, missing, blocked, focus-changed, "Send to active slot" uses the current text, hotkey during delivery.
4. Frontend vitest: slot bar reducer, badges, settings, Windows-disabled state.
5. `cargo clippy --workspace --all-targets -D warnings` and `cargo tauri build`.
6. Optional local macOS integration test (`cargo test -p vq-inject --features mac-it -- --ignored`): spawns TextEdit, binds, delivers via both paths, verifies by AX read-back. It needs Accessibility for the test runner, so it is **not** part of verify.sh by default.
6w. **Windows CI** (`.github/workflows/desktop.yml`):
   - `cargo test -p vq-inject` and the app's tests run on `windows-latest`;
   - an integration job (`--features win-it -- --ignored`) launches Notepad, binds, delivers via typing and paste, and reads back via UIA. It is **non-blocking** (`continue-on-error`) until it has proven stable on hosted runners.
7. `docs/MANUAL_TEST.md` gains a **Bindings** section **for Windows first** (Teams, Copilot in Edge, Windows Terminal + Claude CLI, Notepad, password field refusal, elevated terminal refusal, clipboard restore incl. an image on the clipboard, focus return), then macOS: Teams, Copilot (browser and VS Code), Terminal and iTerm2 with Claude CLI, a TextEdit/Notes native field, a password field refusal, clipboard restore, focus return, re-match after restart, hotkey conflicts, rebuild re-grant.

## 7. Milestones (v2)
| # | Milestone | Done when |
|---|---|---|
| N1 | `vq-inject`: model, store/re-match, planner (pure) + MacInjector + UnsupportedInjector | gate 1, plus clippy; MacInjector compiles |
| N1w | `WindowsInjector` (§4.8) + `win-it` integration test + Windows CI jobs | gate 0 cross-check, plus Windows CI green (integration job may be non-blocking) |
| N2 | Core `FinalAccepted`; DeliveryManager; global hotkeys + sounds; Tauri commands/events; slot bar, badges, Send-to-active, Settings → Bindings | gates 2–5 |
| N3 | Reviewer + adversary pass (safety: wrong-target injection, secure input, focus and clipboard races, re-match ambiguity, hotkey conflicts), fixer, docs (README, MANUAL_TEST Bindings section) | all gates; owner runs the Bindings checklist |

Owner-device checks are done by the owner. N3 can't be completed by agents alone.

## 8. Owner-resolved questions
- O1: Binding a slot also makes it active. **Yes.**
- O2: "Send to active slot" is **disabled when Off**.

## v2.2 BLE polling mode
iOS 26.1+ refuses CCCD writes from some third-party centrals (Windows: HRESULT 0x80650003 while subscribing to TX; Apple forums thread 812318, no workaround). The desktop therefore falls back, per connection, to **polling**: if `subscribe(TX)` fails it reads TX repeatedly (empty read: wait 50 ms; data: deliver and read again at once). The phone treats a central that writes RX without subscribing as a poll peer, answers each TX read with one queued frame (or empty), and drops it after 60 s of silence. Normative text: protocol/README.md §2.2. `VQ_BLE_FORCE_POLL=1` forces it on the desktop. The "devices seen" counter now counts unique peripheral ids since the scan started.

---

## v2.3 — Windows: reversed Bluetooth roles (owner decision 2026-10-04)

**Why.** On iOS 26.1+ the iPhone, acting as a GATT peripheral, refuses app-level GATT access from non-Apple centrals: subscribe, read and write all fail. That holds even when the link is OS-bonded and encrypted. Bluetooth LE Explorer showed the same thing for the phone's standard services (Battery and Current Time were "Unreachable"). macOS is unaffected. Wi-Fi was rejected because the owner's PC is on a corporate network.

**Design.**
- **The PC is the peripheral and the iPhone is the central.** This applies to Windows hosts only. macOS keeps the v1 roles (the iPhone is the peripheral).
- **New GATT service on the PC** (`HOST_SERVICE_UUID`, distinct from the v1 `SERVICE_UUID`; constants live in vq-protocol, documented in protocol/README.md §2.3):
  - `H_RX`: phone → desktop, Write (with response).
  - `H_TX`: desktop → phone, Notify.
  - Both use protection level **Plain**, so no OS bonding is needed. Owners should remove any OS-level pairing between the phone and the PC.
- **Advertising.** The Windows host advertises `HOST_SERVICE_UUID` (connectable, discoverable) using WinRT `GattServiceProvider`. If the adapter lacks peripheral-role support (`BluetoothAdapter.IsPeripheralRoleSupported == false`), the toolbar says "This PC's Bluetooth adapter can't accept connections from the iPhone (peripheral role not supported)".
- **Session flow.** Everything above the transport is unchanged: framing, envelope, hello, pairing, the session, and delivery. In particular:
  - when the iPhone subscribes to `H_TX`, the desktop treats that as "connected" and sends its `hello` by notification to that client, exactly as v1 does after subscribing;
  - the phone replies by writing to `H_RX`;
  - frame size: the desktop uses the GattSession MaxPduSize − 3, and the phone uses `maximumWriteValueLength(for: .withResponse)`. Both are capped at 512.
- **Multiple clients.** Notifications are targeted per subscribed client (`NotifyValueAsync(value, client)`). A client unsubscribing, or its session closing, counts as a disconnect.
- **iPhone.** The app runs **both** roles in the foreground:
  - the existing peripheral, for Macs;
  - a new `BLECentralTransport` (`CBCentralManager`) that scans for `HOST_SERVICE_UUID`, connects, discovers, subscribes to `H_TX` and writes `H_RX`.

  Hosts from both transports appear in the one host list. Reconnect uses backoff (1, 2, 4, 8, max 15 s), and the central role stops when the app goes to the background.
- **Windows desktop transport.** A Windows-only `BlePeripheralTransport` in vq-host-core (`cfg(windows)`, `windows` crate) implements the existing `Transport` trait. On Windows it **replaces** the central transport; macOS keeps using `BleCentralTransport`.
- **Testing.**
  - Pure logic (client/peer bookkeeping, MTU choice, the reconnect policy) gets unit tests on both sides.
  - Windows code is cross-checked here and unit-tested on the Windows CI runner.
  - Real-radio behaviour is verified by the owner's checklist, added to MANUAL_TEST.md.
