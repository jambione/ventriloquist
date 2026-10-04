# Ventriloquist — Specification v2: Bindings

Status: **APPROVED by owner 2026-10-04**, from the owner interview. This is a delta on [SPEC.md](SPEC.md) (v1). Everything in v1 still applies unless this document changes it.

**Summary.** The desktop app can *bind* up to 9 target text boxes in other apps (Teams chat, Copilot chat, a terminal running the Claude CLI, …) to numbered **slots**. One slot is *active*. When a new final utterance arrives, the desktop inserts it into the active slot's target, then returns focus to wherever the user was. Global hotkeys select slots and create bindings.

---

## 1. Goals and non-goals

### Goals
- B-G1. Bind the focused text box of any app to slot 1–9 with a global hotkey, and select the active slot with another global hotkey.
- B-G2. Deliver each **new final** utterance to the active slot's target. Use the best insertion method for each target and never lose the user's focus or clipboard.
- B-G3. Make target apps' "Enter = send" behaviour safe: line breaks are soft (Shift+Enter), and pressing Enter at the end is an opt-in per slot.
- B-G4. Make it visible where every utterance went (or why it didn't go).

### Non-goals (v2)
- **Windows bindings.** The Windows build keeps the v1 behaviour, and the slot UI says "Bindings are macOS-only in this version". The code is structured so a Windows injector can be added later (§3).
- No phone or protocol changes. The iPhone app is unchanged, and the protocol stays at `v: 1`.
- No live/partial typing, and no re-typing of corrections. An `edit` updates the Ventriloquist entry only.
- No on-screen toast or menu bar item. Feedback is sounds plus the Ventriloquist window.

## 2. Owner decisions (v2 interview)

| Topic | Decision |
|---|---|
| Typical targets | Teams chat, Copilot chat (web/Electron), terminal running Claude CLI, plus native text fields |
| Insertion method | **Auto**: Accessibility insertion where the target supports it, otherwise activate the window and type keystrokes (§4.3) |
| When | **Finals only.** Edits are never re-typed |
| Platforms | **macOS first.** Windows later |
| Create binding | Hotkey while the target field is focused: **Ctrl+Option+Shift+1…9** |
| Select slot | **Ctrl+Shift+1…9** selects slot N. **Ctrl+Shift+0** = Off (display only) |
| Submit (Enter) | Per-slot **auto-submit** switch, **default off** |
| Line breaks | Inserted as **Shift+Enter** (soft newline) |
| Focus | **Return to where the user was** after inserting |
| Persistence | **Best-effort re-match** after restarts; otherwise the slot shows "unbound" |
| Target missing | **Display only + warning**. Never fall back to another window |
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
                                                        ├─ MacInjector (AX + CGEvent + NSPasteboard + NSWorkspace)
                                                        └─ UnsupportedInjector (other OSes)
```

- **New crate `desktop/inject` (`vq-inject`)**, part of the workspace.
  - The model, the store/re-match logic and the **delivery planner are pure Rust**, OS-independent and fully unit-tested.
  - The macOS executor lives behind `cfg(target_os = "macos")`; every other OS gets `UnsupportedInjector`.
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
2. **Refuse** (result **`blocked`**) when:
   - the target element is a secure text field;
   - secure event input is enabled system-wide (`IsSecureEventInputEnabled()`, e.g. a password prompt is up).
3. **Plan** with the pure planner `plan_delivery(caps, text, settings)`, where caps = {ax_insertable, app category}:
   - **AX path:** only if the element is a native text field/area whose `AXSelectedText` is settable, and the app is not on the keystroke-preferred list (browsers, Electron apps incl. Teams/VS Code/Slack, terminals: Terminal, iTerm2, Warp, Ghostty, WezTerm, Alacritty, kitty). Set `AXSelectedText` to the text, inserting at the cursor and replacing any selection. If text has line breaks, insert them as `\n` — AX insertion doesn't trigger send. **No activation needed.** Read the value back to confirm; if that fails, fall through to the keystroke path.
   - **Keystroke path:**
     1. Remember the current frontmost app.
     2. Activate the target app and raise the bound window (`AXRaise`, `NSRunningApplication.activate`).
     3. Re-focus the bound element (`AXFocused = true`) if it is still valid.
     4. Wait until the target is frontmost (poll ≤ 500 ms; else result `failed`).
     5. Insert the text:
        - **≤ 200 characters:** type it as Unicode keyboard events (`CGEventKeyboardSetUnicodeString`, chunks of ≤ 20 UTF-16 units). Each line break is **Shift+Return**.
        - **> 200 characters:** **paste**, line by line:
          1. Snapshot every pasteboard item and type.
          2. Set the line's text and press Cmd+V, pressing Shift+Return between lines.
          3. Restore the snapshot ~250 ms after the last paste.
          4. If the user changed the clipboard in between (`changeCount` differs from the one we set), do **not** restore.
     6. If the slot's **auto-submit** is on, press Return.
     7. Re-activate the remembered app (unless it *was* the target).
4. Text is the entry's final text **exactly**: no trimming, no added prefix or suffix. Control characters other than `\n`/`\t` are dropped from typing (logged); `\r\n` is treated as one line break.
5. **Result** `sent` / `missing` / `blocked` / `failed(reason)` is shown as a badge on the entry (§4.5) and logged to stderr when `VQ_LOG=1`. It is **not** written to the Markdown log, whose format is unchanged.

### 4.4 Ordering and races
- Deliveries are serial and FIFO. A second final arriving during a delivery waits.
- Keyboard events are posted only after the target is confirmed frontmost. If the frontmost app changes during typing (the user clicked elsewhere), stop and report `failed("focus changed")`. Text already typed stays.
- Slot hotkeys pressed during a delivery take effect for the next delivery.

### 4.5 Desktop UI additions (Ventriloquist window)
- **Slot bar** under the toolbar:
  - chips **Off · 1 … 9**. Each bound chip shows `N · App — window title` (truncated, full text in a tooltip).
  - Unbound chips are dimmed; the active chip is highlighted. Click a chip to select it, the same as the hotkey.
  - Each bound chip has a ⋯ menu: **Auto-submit (Enter)** toggle, **Unbind**.
  - Re-matched-but-unverified chips show a small "?" until the first successful delivery.
- **Entry badge:** `→ 2 · Teams ✓`, `not sent (Off)`, `✗ slot 2 missing`, `⚠ blocked (secure input)`, `✗ failed: <reason>`, or `sending…`.
- **"Send to active slot"** button per entry (next to Copy): delivers that entry's **current** text, including corrections, to the active slot with the same rules. It is disabled when Off.
- **Settings → Bindings:**
  - **Accessibility permission:** status, with an "Open System Settings" button.
  - **Hotkey modifiers**, two pickers:
    - select: default Ctrl+Shift;
    - bind: default Ctrl+Option+Shift.
    - Digits stay 0–9. If a combination fails to register, it is shown as "taken by another app".
  - The list of slots, with Unbind.
- The **Windows** build shows the slot bar disabled with "Bindings are macOS-only in this version".

### 4.6 Persistence and re-match
- `bindings.json` lives in the config dir: an atomic write, version field, slots 1–9, and the active slot.
- **Re-match**, on start and when a live reference is invalid:
  1. Find running apps with the bundle id.
  2. Look for a window whose title equals the saved title exactly.
  3. If none, and the app has exactly **one** standard window, use it and update the saved title.
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

## 5. Security and safety
- Text is only ever injected into the **bound** target, never the frontmost app by fallback.
- Secure text fields and secure event input are never typed into (§4.3).
- Delivery is triggered only by `FinalAccepted` (authenticated, first-acceptance finals) or by the user's explicit "Send to active slot" click.
- Clipboard contents are restored, and never logged.
- Auto-submit is off by default for every slot.
- **Spec-level risk, accepted by the owner's choice of auto-submit per slot:** with auto-submit on for a terminal slot, dictated text is executed by the shell or Claude CLI. The slot chip shows a "⏎" marker when auto-submit is on.

## 6. Verification (v2 gates, added to scripts/verify.sh)
1. `cargo test -p vq-inject`: planner (every path, line breaks, the 200-character threshold, auto-submit, control characters, CRLF), store/re-match (exact title, single window, ambiguous → unbound, corrupt file → defaults + warning), slot selection logic.
2. `cargo test -p vq-host-core --features dev-tcp`: `FinalAccepted` fires exactly once per id across duplicates, stale revisions, edits and restart re-delivery.
3. DeliveryManager tests with a **fake Injector**: serial FIFO, Off, missing, blocked, focus-changed, "Send to active slot" uses the current text, hotkey during delivery.
4. Frontend vitest: slot bar reducer, badges, settings, Windows-disabled state.
5. `cargo clippy --workspace --all-targets -D warnings` and `cargo tauri build`.
6. Optional local macOS integration test (`cargo test -p vq-inject --features mac-it -- --ignored`): spawns TextEdit, binds, delivers via both paths, verifies by AX read-back. It needs Accessibility for the test runner, so it is **not** part of verify.sh by default.
7. `docs/MANUAL_TEST.md` gains a **Bindings** section: Teams, Copilot (browser and VS Code), Terminal and iTerm2 with Claude CLI, a TextEdit/Notes native field, a password field refusal, clipboard restore, focus return, re-match after restart, hotkey conflicts, rebuild re-grant.

## 7. Milestones (v2)
| # | Milestone | Done when |
|---|---|---|
| N1 | `vq-inject`: model, store/re-match, planner (pure) + MacInjector + UnsupportedInjector | gate 1, plus clippy; MacInjector compiles |
| N2 | Core `FinalAccepted`; DeliveryManager; global hotkeys + sounds; Tauri commands/events; slot bar, badges, Send-to-active, Settings → Bindings | gates 2–5 |
| N3 | Reviewer + adversary pass (safety: wrong-target injection, secure input, focus and clipboard races, re-match ambiguity, hotkey conflicts), fixer, docs (README, MANUAL_TEST Bindings section) | all gates; owner runs the Bindings checklist |

Owner-device checks are done by the owner. N3 can't be completed by agents alone.

## 8. Owner-resolved questions
- O1: Binding a slot also makes it active. **Yes.**
- O2: "Send to active slot" is **disabled when Off**.
