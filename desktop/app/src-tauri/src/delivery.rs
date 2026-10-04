//! DeliveryManager (SPEC_V2 §3, §4.1–§4.4): owns the bindings store and the
//! platform [`Injector`] on one dedicated thread, and processes every
//! command (deliveries, hotkeys, UI actions) from one FIFO queue. AX / UIA
//! and key-event calls block, so nothing here runs on the host event loop.
//!
//! Ordering (§4.4): deliveries are serial and FIFO. A hotkey or UI command
//! queued behind a delivery runs after it (and after any deliveries queued
//! before it), so it affects the *next* delivery that starts afterwards.
//!
//! The UI is told through a [`Sink`]: `delivery` events (one per state
//! change of an entry's delivery), `slots` events (the whole slot bar) and
//! notices. [`DeliveryManager::snapshot`] returns the same state for a page
//! reload, plus the recent deliveries.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use serde::Serialize;
use vq_host_core::events::HostEvent;
use vq_host_core::transcript::{Entry, EntryState};
use vq_inject::{
    plan_delivery, rematch, secure_refusal, BindingsStore, DeliveryMethod, DeliveryResult,
    InjectError, Injector, NewlineMode, RematchOutcome, SelectOutcome, SlotId, Sound,
};

use crate::hotkeys::HotkeyView;

/// Recent deliveries kept for page reloads.
const MAX_DELIVERIES: usize = 500;
/// Entry texts kept for "Send to active slot" (the core keeps 500 entries).
const MAX_TEXTS: usize = 600;
/// How long `start` waits for the start-up re-match.
const START_WAIT: Duration = Duration::from_secs(3);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

// ------------------------------------------------------------------ views

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Sending,
    Sent,
    /// Active slot is Off: nothing sent.
    Off,
    Missing,
    Blocked,
    Failed,
}

/// One state of the delivery of one entry (the `delivery` event).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeliveryEvent {
    pub entry_id: String,
    pub slot: Option<u8>,
    /// The bound app's name (untrusted text: render with textContent).
    pub app_name: Option<String>,
    pub status: DeliveryStatus,
    pub reason: Option<String>,
    pub method: Option<DeliveryMethod>,
    /// Started by the "Send to active slot" button.
    pub manual: bool,
}

/// `live`: bound in this session or delivered to since; `unverified`:
/// re-matched, no delivery yet ("?"); `unbound`: not found ("rebind").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotStatus {
    Live,
    Unverified,
    Unbound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SlotView {
    pub slot: u8,
    pub app_name: String,
    pub window_title: String,
    pub element_role: String,
    pub status: SlotStatus,
    pub auto_submit: bool,
    /// `shift_enter` / `spaces`.
    pub newline_mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SlotsView {
    /// 0 = Off, 1..=9.
    pub active: u8,
    pub slots: Vec<SlotView>,
    pub hotkeys: HotkeyView,
    /// Only in [`DeliveryManager::snapshot`]; empty in `slots` events.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deliveries: Vec<DeliveryEvent>,
}

/// Something the user should be told that is not an entry's delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Notice {
    /// `accessibility_needed`, `bind_failed`, `save_failed`, `bindings_warning`.
    pub code: &'static str,
    pub slot: Option<u8>,
    pub detail: Option<String>,
}

/// Where the manager reports to. Must not block.
pub trait Sink: Send + Sync + 'static {
    fn delivery(&self, ev: &DeliveryEvent);
    fn slots(&self, view: &SlotsView);
    fn notice(&self, n: &Notice);
}

// --------------------------------------------------------------- commands

enum Cmd {
    Final { entry_id: String, text: String },
    SendToActive { entry_id: String },
    Bind(SlotId),
    Select(u8),
    Unbind(SlotId),
    SetSettings { slot: SlotId, auto_submit: Option<bool>, newline_mode: Option<String> },
    SetHotkeys(HotkeyView),
    Rematch,
    #[allow(dead_code)]
    Barrier(Sender<()>),
    Shutdown,
}

struct Shared {
    view: SlotsView,
    deliveries: VecDeque<DeliveryEvent>,
}

#[derive(Default)]
struct Texts {
    map: HashMap<String, TextEntry>,
    order: VecDeque<String>,
}

struct TextEntry {
    rev: u32,
    /// `final` or `edit` (not a partial or interrupted utterance).
    sendable: bool,
    text: String,
}

impl Texts {
    fn note(&mut self, e: &Entry) {
        let id = e.id.to_string();
        let sendable = matches!(e.state, EntryState::Final | EntryState::Edit);
        match self.map.get_mut(&id) {
            Some(t) if e.rev >= t.rev => {
                *t = TextEntry { rev: e.rev, sendable, text: e.text.clone() };
            }
            Some(_) => {}
            None => {
                self.map.insert(id.clone(), TextEntry { rev: e.rev, sendable, text: e.text.clone() });
                self.order.push_back(id);
                while self.order.len() > MAX_TEXTS {
                    if let Some(old) = self.order.pop_front() {
                        self.map.remove(&old);
                    }
                }
            }
        }
    }

    fn remove(&mut self, id: &str) {
        if self.map.remove(id).is_some() {
            self.order.retain(|x| x != id);
        }
    }
}

fn record(shared: &Mutex<Shared>, sink: &dyn Sink, ev: DeliveryEvent) {
    {
        let mut sh = lock(shared);
        sh.deliveries.retain(|d| d.entry_id != ev.entry_id);
        sh.deliveries.push_back(ev.clone());
        while sh.deliveries.len() > MAX_DELIVERIES {
            sh.deliveries.pop_front();
        }
    }
    sink.delivery(&ev);
}

// ---------------------------------------------------------------- manager

/// Handle to the delivery thread. Cheap to call from any thread.
pub struct DeliveryManager {
    tx: Sender<Cmd>,
    shared: Arc<Mutex<Shared>>,
    texts: Arc<Mutex<Texts>>,
    sink: Arc<dyn Sink>,
    injector: Arc<dyn Injector>,
    /// Signalled when the thread exits (for the bounded wait in `shutdown`).
    done: Mutex<Receiver<()>>,
}

impl DeliveryManager {
    /// Load `bindings.json` from `dir`, re-match, and start the thread.
    pub fn start(
        dir: PathBuf,
        injector: Box<dyn Injector>,
        sink: Arc<dyn Sink>,
        hotkeys: HotkeyView,
    ) -> Self {
        let injector: Arc<dyn Injector> = Arc::from(injector);
        let shared = Arc::new(Mutex::new(Shared {
            view: SlotsView { active: 0, slots: Vec::new(), hotkeys, deliveries: Vec::new() },
            deliveries: VecDeque::new(),
        }));
        let texts = Arc::new(Mutex::new(Texts::default()));
        let (tx, rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = Worker {
            dir,
            store: BindingsStore::default(),
            inj: injector.clone(),
            sink: sink.clone(),
            shared: shared.clone(),
            texts: texts.clone(),
            status: BTreeMap::new(),
        };
        thread::Builder::new()
            .name("vq-delivery".into())
            .spawn(move || {
                worker.run(rx, ready_tx);
                let _ = done_tx.send(());
            })
            .expect("cannot spawn the delivery thread");
        let _ = ready_rx.recv_timeout(START_WAIT);
        DeliveryManager { tx, shared, texts, sink, injector, done: Mutex::new(done_rx) }
    }

    /// Feed every host event through here: entry texts are tracked for
    /// "Send to active slot", and `FinalAccepted` triggers delivery (the
    /// only automatic trigger, SPEC_V2 §3).
    pub fn observe(&self, ev: &HostEvent) {
        match ev {
            HostEvent::EntryUpserted { entry } => lock(&self.texts).note(entry),
            HostEvent::FinalAccepted { entry } => {
                lock(&self.texts).note(entry);
                self.on_final(entry.id.to_string(), entry.text.clone());
            }
            HostEvent::Snapshot { entries, .. } => {
                let mut t = lock(&self.texts);
                for e in entries {
                    t.note(e);
                }
            }
            HostEvent::EntryEvicted { id } => lock(&self.texts).remove(&id.to_string()),
            _ => {}
        }
    }

    /// A new final utterance: deliver `text` exactly.
    pub fn on_final(&self, entry_id: String, text: String) {
        self.announce_sending(&entry_id, false);
        let _ = self.tx.send(Cmd::Final { entry_id, text });
    }

    /// "Send to active slot": the entry's *current* text, read when the
    /// delivery starts. Refused when Off, unknown, or not yet final.
    pub fn send_to_active(&self, entry_id: &str) -> Result<(), String> {
        if lock(&self.shared).view.active == 0 {
            return Err("no active slot (Off)".into());
        }
        match lock(&self.texts).map.get(entry_id) {
            None => return Err("unknown entry".into()),
            Some(t) if !t.sendable => return Err("the entry is not final yet".into()),
            Some(_) => {}
        }
        self.announce_sending(entry_id, true);
        let _ = self.tx.send(Cmd::SendToActive { entry_id: entry_id.to_string() });
        Ok(())
    }

    fn announce_sending(&self, entry_id: &str, manual: bool) {
        let (active, name) = {
            let sh = lock(&self.shared);
            let name = sh
                .view
                .slots
                .iter()
                .find(|s| s.slot == sh.view.active)
                .map(|s| s.app_name.clone());
            (sh.view.active, name)
        };
        if active == 0 {
            return; // the worker reports `off`
        }
        record(
            &self.shared,
            &*self.sink,
            DeliveryEvent {
                entry_id: entry_id.to_string(),
                slot: Some(active),
                app_name: name,
                status: DeliveryStatus::Sending,
                reason: None,
                method: None,
                manual,
            },
        );
    }

    /// Bind slot `n` (1..=9) to the focused text box; also selects it.
    pub fn bind(&self, n: u8) -> Result<(), String> {
        let slot = SlotId::new(n).ok_or("slot must be 1 to 9")?;
        let _ = self.tx.send(Cmd::Bind(slot));
        Ok(())
    }

    /// 0 = Off, 1..=9 = slot.
    pub fn select(&self, digit: u8) -> Result<(), String> {
        if digit > 9 {
            return Err("slot must be 0 to 9".into());
        }
        let _ = self.tx.send(Cmd::Select(digit));
        Ok(())
    }

    pub fn unbind(&self, n: u8) -> Result<(), String> {
        let slot = SlotId::new(n).ok_or("slot must be 1 to 9")?;
        let _ = self.tx.send(Cmd::Unbind(slot));
        Ok(())
    }

    pub fn set_settings(
        &self,
        n: u8,
        auto_submit: Option<bool>,
        newline_mode: Option<String>,
    ) -> Result<(), String> {
        let slot = SlotId::new(n).ok_or("slot must be 1 to 9")?;
        let _ = self.tx.send(Cmd::SetSettings { slot, auto_submit, newline_mode });
        Ok(())
    }

    /// New hotkey registration state (from `hotkeys.rs`).
    pub fn set_hotkeys(&self, v: HotkeyView) {
        let _ = self.tx.send(Cmd::SetHotkeys(v));
    }

    /// Re-run the re-match for unbound slots (e.g. after permission was
    /// granted). A no-op when none is unbound.
    pub fn rematch_unbound(&self) {
        let any = lock(&self.shared).view.slots.iter().any(|s| s.status == SlotStatus::Unbound);
        if any {
            let _ = self.tx.send(Cmd::Rematch);
        }
    }

    /// The slot state plus recent deliveries, for a (re)loaded page.
    pub fn snapshot(&self) -> SlotsView {
        let sh = lock(&self.shared);
        let mut v = sh.view.clone();
        v.deliveries = sh.deliveries.iter().cloned().collect();
        v
    }

    pub fn injector(&self) -> &Arc<dyn Injector> {
        &self.injector
    }

    /// Block until everything queued so far has been processed.
    #[allow(dead_code)]
    pub fn flush(&self) {
        let (tx, rx) = mpsc::channel();
        if self.tx.send(Cmd::Barrier(tx)).is_ok() {
            let _ = rx.recv();
        }
    }

    /// Stop the thread after the queued commands; waits at most `timeout`
    /// (a delivery stuck in an OS call must not hang quitting). Never panics.
    /// Returns whether the thread stopped in time.
    pub fn shutdown(&self, timeout: Duration) -> bool {
        let _ = self.tx.send(Cmd::Shutdown);
        lock(&self.done).recv_timeout(timeout).is_ok()
    }
}

impl Drop for DeliveryManager {
    fn drop(&mut self) {
        let _ = self.tx.send(Cmd::Shutdown);
    }
}

// ----------------------------------------------------------------- worker

struct Worker {
    dir: PathBuf,
    store: BindingsStore,
    inj: Arc<dyn Injector>,
    sink: Arc<dyn Sink>,
    shared: Arc<Mutex<Shared>>,
    texts: Arc<Mutex<Texts>>,
    status: BTreeMap<SlotId, SlotStatus>,
}

fn newline_mode_of(s: &vq_inject::SlotSettings) -> Option<String> {
    Some(match s.newline_mode {
        NewlineMode::ShiftEnter => "shift_enter",
        NewlineMode::Spaces => "spaces",
    }
    .to_string())
}

fn set_newline_mode(store: &mut BindingsStore, slot: SlotId, mode: &str) -> bool {
    let m = match mode {
        "shift_enter" => NewlineMode::ShiftEnter,
        "spaces" => NewlineMode::Spaces,
        _ => return false,
    };
    store.set_newline_mode(slot, m)
}

impl Worker {
    fn run(mut self, rx: Receiver<Cmd>, ready: Sender<()>) {
        self.startup();
        let _ = ready.send(());
        while let Ok(cmd) = rx.recv() {
            match cmd {
                Cmd::Final { entry_id, text } => self.deliver(&entry_id, &text, false),
                Cmd::SendToActive { entry_id } => {
                    let text = lock(&self.texts).map.get(&entry_id).map(|t| t.text.clone());
                    match text {
                        Some(t) => self.deliver(&entry_id, &t, true),
                        None => self.finish(&entry_id, None, None, DeliveryStatus::Failed, Some("unknown entry".into()), None, true),
                    }
                }
                Cmd::Bind(slot) => self.bind(slot),
                Cmd::Select(d) => self.select(d),
                Cmd::Unbind(slot) => self.unbind(slot),
                Cmd::SetSettings { slot, auto_submit, newline_mode } => {
                    self.set_settings(slot, auto_submit, newline_mode)
                }
                Cmd::SetHotkeys(v) => {
                    lock(&self.shared).view.hotkeys = v;
                    self.publish();
                }
                Cmd::Rematch => {
                    self.rematch_all(true);
                    self.publish();
                }
                Cmd::Barrier(tx) => {
                    let _ = tx.send(());
                }
                Cmd::Shutdown => break,
            }
        }
    }

    fn startup(&mut self) {
        let (store, warning) = BindingsStore::load(&self.dir);
        self.store = store;
        if let Some(w) = warning {
            self.sink.notice(&Notice { code: "bindings_warning", slot: None, detail: Some(w) });
        }
        let records: Vec<_> = self.store.records().cloned().collect();
        for r in &records {
            self.inj.assign_saved(r.slot, &r.target);
        }
        self.rematch_all(false);
        // §4.2: the active slot is restored only if it re-matched.
        if let Some(s) = self.store.active().slot() {
            if self.status.get(&s) != Some(&SlotStatus::Unverified) {
                self.store.select(0);
                self.save();
            }
        }
        self.publish();
    }

    /// Best-effort re-match for display (§4.6); `only_unbound` limits it to
    /// slots currently shown as unbound.
    fn rematch_all(&mut self, only_unbound: bool) {
        let records: Vec<_> = self.store.records().cloned().collect();
        let mut changed_title = false;
        for r in records {
            if only_unbound && self.status.get(&r.slot) != Some(&SlotStatus::Unbound) {
                continue;
            }
            let windows = self.inj.running_windows(&r.target.app_id);
            match rematch(&r.target, &windows) {
                RematchOutcome::Matched { window, .. } => {
                    if window.title != r.target.window_title
                        && self.store.update_title(r.slot, &window.title)
                    {
                        changed_title = true;
                    }
                    self.status.insert(r.slot, SlotStatus::Unverified);
                }
                RematchOutcome::Unbound(_) => {
                    self.status.insert(r.slot, SlotStatus::Unbound);
                }
            }
        }
        if changed_title {
            self.save();
        }
    }

    fn save(&self) {
        if let Err(e) = self.store.save(&self.dir) {
            self.sink.notice(&Notice {
                code: "save_failed",
                slot: None,
                detail: Some(e.to_string()),
            });
        }
    }

    fn build_view(&self, hotkeys: HotkeyView) -> SlotsView {
        let slots = self
            .store
            .records()
            .map(|r| SlotView {
                slot: r.slot.get(),
                app_name: r.target.app_name.clone(),
                window_title: r.target.window_title.clone(),
                element_role: r.target.element_role.clone(),
                status: self.status.get(&r.slot).copied().unwrap_or(SlotStatus::Unbound),
                auto_submit: r.settings.auto_submit,
                newline_mode: newline_mode_of(&r.settings),
            })
            .collect();
        SlotsView { active: self.store.active().digit(), slots, hotkeys, deliveries: Vec::new() }
    }

    fn publish(&self) {
        let view = {
            let mut sh = lock(&self.shared);
            let v = self.build_view(sh.view.hotkeys.clone());
            sh.view = v.clone();
            v
        };
        self.sink.slots(&view);
    }

    fn set_status(&mut self, slot: SlotId, s: SlotStatus) {
        if self.status.insert(slot, s) != Some(s) {
            self.publish();
        }
    }

    // ---- hotkey / UI commands

    fn bind(&mut self, slot: SlotId) {
        match self.inj.capture_focused() {
            Ok(c) => {
                self.store.bind(slot, c.target.clone());
                self.inj.assign(slot, c);
                self.status.insert(slot, SlotStatus::Live);
                self.save();
                self.inj.play_sound(Sound::Selected);
                self.publish();
            }
            Err(e) => {
                self.inj.play_sound(Sound::Error);
                if e == InjectError::NotTrusted {
                    self.inj.is_trusted(true); // the system prompt, first time only
                    self.sink.notice(&Notice {
                        code: "accessibility_needed",
                        slot: Some(slot.get()),
                        detail: None,
                    });
                } else {
                    self.sink.notice(&Notice {
                        code: "bind_failed",
                        slot: Some(slot.get()),
                        detail: Some(e.to_string()),
                    });
                }
            }
        }
    }

    fn select(&mut self, digit: u8) {
        match self.store.select(digit) {
            Some(SelectOutcome::Selected(_)) => {
                self.inj.play_sound(Sound::Selected);
                self.save();
                self.publish();
            }
            Some(SelectOutcome::Off) => {
                self.inj.play_sound(Sound::Off);
                self.save();
                self.publish();
            }
            Some(SelectOutcome::Empty(_)) => self.inj.play_sound(Sound::Empty),
            None => {}
        }
    }

    fn unbind(&mut self, slot: SlotId) {
        if self.store.unbind(slot) {
            self.inj.release(slot);
            self.status.remove(&slot);
            self.save();
            self.publish();
        }
    }

    fn set_settings(&mut self, slot: SlotId, auto_submit: Option<bool>, newline_mode: Option<String>) {
        let mut ok = true;
        if let Some(on) = auto_submit {
            ok &= self.store.set_auto_submit(slot, on);
        }
        if let Some(m) = newline_mode {
            ok &= set_newline_mode(&mut self.store, slot, &m);
        }
        if ok {
            self.save();
        }
        self.publish();
    }

    // ---- delivery

    #[allow(clippy::too_many_arguments)]
    fn finish(
        &self,
        entry_id: &str,
        slot: Option<SlotId>,
        app_name: Option<String>,
        status: DeliveryStatus,
        reason: Option<String>,
        method: Option<DeliveryMethod>,
        manual: bool,
    ) {
        let ev = DeliveryEvent {
            entry_id: entry_id.to_string(),
            slot: slot.map(SlotId::get),
            app_name,
            status,
            reason,
            method,
            manual,
        };
        log::debug!("delivery {ev:?}");
        record(&self.shared, &*self.sink, ev);
    }

    /// Deliver `text` to the active slot (§4.3). Never falls back to any
    /// other window.
    fn deliver(&mut self, entry_id: &str, text: &str, manual: bool) {
        let Some(slot) = self.store.active().slot() else {
            self.finish(entry_id, None, None, DeliveryStatus::Off, None, None, manual);
            return;
        };
        let Some(rec) = self.store.get(slot).cloned() else {
            self.finish(entry_id, None, None, DeliveryStatus::Off, None, None, manual);
            return;
        };
        let name = Some(rec.target.app_name.clone());
        let fail = |this: &Self, st: DeliveryStatus, why: String| {
            this.finish(entry_id, Some(slot), name.clone(), st, Some(why), None, manual)
        };

        // 1. Resolve (re-match if the live reference is gone).
        let rt = match self.inj.resolve(slot) {
            Ok(rt) => rt,
            Err(InjectError::Missing) => {
                self.set_status(slot, SlotStatus::Unbound);
                self.finish(entry_id, Some(slot), name, DeliveryStatus::Missing, None, None, manual);
                return;
            }
            Err(InjectError::NotTrusted) => {
                self.sink.notice(&Notice {
                    code: "accessibility_needed",
                    slot: Some(slot.get()),
                    detail: None,
                });
                fail(self, DeliveryStatus::Failed, InjectError::NotTrusted.to_string());
                return;
            }
            Err(e) => {
                fail(self, DeliveryStatus::Failed, e.to_string());
                return;
            }
        };
        if rt.title_changed && self.store.update_title(slot, &rt.target.window_title) {
            self.save();
            self.publish();
        }
        if self.status.get(&slot).is_none_or(|s| *s == SlotStatus::Unbound) {
            self.set_status(slot, SlotStatus::Unverified);
        }

        // 2. Refuse (secure field / secure input / elevated).
        let mut caps = match self.inj.caps(&rt) {
            Ok(c) => c,
            Err(e) => {
                fail(self, DeliveryStatus::Failed, e.to_string());
                return;
            }
        };
        if self.inj.secure_input_enabled() {
            caps.secure_input = true;
        }
        if let Some(why) = secure_refusal(&caps) {
            fail(self, DeliveryStatus::Blocked, why);
            return;
        }

        // 3. Plan and execute.
        let plan = plan_delivery(&caps, text, &rec.settings);
        if let Some(why) = &plan.blocked {
            fail(self, DeliveryStatus::Blocked, why.clone());
            return;
        }
        if plan.is_noop() {
            fail(self, DeliveryStatus::Failed, "nothing to send".into());
            return;
        }
        if plan.dropped_controls > 0 {
            log::debug!("{} control characters dropped from the text", plan.dropped_controls);
        }
        match self.inj.execute(&plan, &rt) {
            DeliveryResult::Sent { method } => {
                self.set_status(slot, SlotStatus::Live);
                self.finish(entry_id, Some(slot), name, DeliveryStatus::Sent, None, Some(method), manual);
            }
            DeliveryResult::Missing => {
                self.set_status(slot, SlotStatus::Unbound);
                self.finish(entry_id, Some(slot), name, DeliveryStatus::Missing, None, None, manual);
            }
            DeliveryResult::Blocked { reason } => fail(self, DeliveryStatus::Blocked, reason),
            DeliveryResult::Failed { reason } => fail(self, DeliveryStatus::Failed, reason),
        }
    }
}

// ------------------------------------------------------------------ tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::{AtomicU64, Ordering};
    use vq_inject::{
        Action, BindingTarget, CapturedBinding, Plan, ResolvedTarget, TargetCaps, WindowInfo,
    };

    // ---- fakes

    #[derive(Default)]
    struct Fake {
        capture: VecDeque<Result<CapturedBinding, InjectError>>,
        assigned: HashMap<SlotId, BindingTarget>,
        missing: HashSet<u8>,
        caps: Option<TargetCaps>,
        secure_input: bool,
        results: VecDeque<DeliveryResult>,
        executed: Vec<(u8, String)>,
        sounds: Vec<Sound>,
        windows: Vec<WindowInfo>,
        entered: Option<Sender<()>>,
        release: Option<Receiver<()>>,
    }

    struct FakeInjector(Mutex<Fake>);

    fn target(app: &str, title: &str) -> BindingTarget {
        BindingTarget {
            app_id: format!("id.{app}"),
            app_name: app.into(),
            window_title: title.into(),
            element_role: "AXTextArea".into(),
            element_subrole: "".into(),
            ax_insertable: false,
        }
    }

    fn captured(app: &str) -> CapturedBinding {
        CapturedBinding { target: target(app, "w"), pid: 1, live: None }
    }

    fn plan_text(plan: &Plan) -> String {
        let mut s = String::new();
        for a in &plan.actions {
            match a {
                Action::AxInsertSelectedText(t) | Action::TypeUnicode(t) | Action::SetClipboard(t) => {
                    s.push_str(t)
                }
                Action::ShiftReturn => s.push('\n'),
                _ => {}
            }
        }
        s
    }

    impl Injector for FakeInjector {
        fn capture_focused(&self) -> vq_inject::Result<CapturedBinding> {
            lock(&self.0).capture.pop_front().unwrap_or(Err(InjectError::NoFocusedElement))
        }
        fn assign(&self, slot: SlotId, c: CapturedBinding) {
            lock(&self.0).assigned.insert(slot, c.target);
        }
        fn assign_saved(&self, slot: SlotId, t: &BindingTarget) {
            lock(&self.0).assigned.insert(slot, t.clone());
        }
        fn release(&self, slot: SlotId) {
            lock(&self.0).assigned.remove(&slot);
        }
        fn resolve(&self, slot: SlotId) -> vq_inject::Result<ResolvedTarget> {
            let f = lock(&self.0);
            if f.missing.contains(&slot.get()) {
                return Err(InjectError::Missing);
            }
            let t = f.assigned.get(&slot).cloned().ok_or(InjectError::Missing)?;
            Ok(ResolvedTarget { slot, target: t, pid: 1, rematched: false, title_changed: false })
        }
        fn caps(&self, t: &ResolvedTarget) -> vq_inject::Result<TargetCaps> {
            Ok(lock(&self.0)
                .caps
                .clone()
                .unwrap_or_else(|| TargetCaps::from_app(&t.target.app_id, false)))
        }
        fn execute(&self, plan: &Plan, t: &ResolvedTarget) -> DeliveryResult {
            let (entered, release) = {
                let mut f = lock(&self.0);
                (f.entered.take(), f.release.take())
            };
            if let Some(e) = entered {
                let _ = e.send(());
            }
            if let Some(r) = release {
                let _ = r.recv();
            }
            let mut f = lock(&self.0);
            f.executed.push((t.slot.get(), plan_text(plan)));
            f.results.pop_front().unwrap_or(DeliveryResult::Sent { method: DeliveryMethod::Type })
        }
        fn is_trusted(&self, _prompt: bool) -> bool {
            true
        }
        fn secure_input_enabled(&self) -> bool {
            lock(&self.0).secure_input
        }
        fn running_windows(&self, app_id: &str) -> Vec<WindowInfo> {
            lock(&self.0).windows.iter().filter(|w| w.app_id == app_id).cloned().collect()
        }
        fn play_sound(&self, s: Sound) {
            lock(&self.0).sounds.push(s);
        }
    }

    #[derive(Default)]
    struct TestSink {
        deliveries: Mutex<Vec<DeliveryEvent>>,
        views: Mutex<Vec<SlotsView>>,
        notices: Mutex<Vec<Notice>>,
    }
    impl Sink for TestSink {
        fn delivery(&self, ev: &DeliveryEvent) {
            lock(&self.deliveries).push(ev.clone());
        }
        fn slots(&self, v: &SlotsView) {
            lock(&self.views).push(v.clone());
        }
        fn notice(&self, n: &Notice) {
            lock(&self.notices).push(n.clone());
        }
    }

    struct Rig {
        fake: Arc<FakeInjector>,
        sink: Arc<TestSink>,
        mgr: DeliveryManager,
        dir: PathBuf,
    }

    /// Lets the test keep a handle on the fake after boxing it.
    struct Shim(Arc<FakeInjector>);
    macro_rules! fwd {
        ($($name:ident($($a:ident: $t:ty),*) -> $r:ty;)*) => {
            $(fn $name(&self, $($a: $t),*) -> $r { self.0.$name($($a),*) })*
        };
    }
    impl Injector for Shim {
        fwd! {
            capture_focused() -> vq_inject::Result<CapturedBinding>;
            release(slot: SlotId) -> ();
            resolve(slot: SlotId) -> vq_inject::Result<ResolvedTarget>;
            caps(t: &ResolvedTarget) -> vq_inject::Result<TargetCaps>;
            execute(p: &Plan, t: &ResolvedTarget) -> DeliveryResult;
            is_trusted(p: bool) -> bool;
            secure_input_enabled() -> bool;
            running_windows(a: &str) -> Vec<WindowInfo>;
            play_sound(s: Sound) -> ();
        }
        fn assign(&self, slot: SlotId, c: CapturedBinding) {
            self.0.assign(slot, c)
        }
        fn assign_saved(&self, slot: SlotId, t: &BindingTarget) {
            self.0.assign_saved(slot, t)
        }
    }

    static N: AtomicU64 = AtomicU64::new(0);

    fn tmpdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "vq-delivery-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn rig_in(dir: PathBuf, setup: impl FnOnce(&mut Fake)) -> Rig {
        let fake = Arc::new(FakeInjector(Mutex::new(Fake::default())));
        setup(&mut lock(&fake.0));
        let sink = Arc::new(TestSink::default());
        let mgr = DeliveryManager::start(
            dir.clone(),
            Box::new(Shim(fake.clone())),
            sink.clone(),
            HotkeyView::default(),
        );
        Rig { fake, sink, mgr, dir }
    }

    fn rig() -> Rig {
        rig_in(tmpdir(), |_| {})
    }

    impl Rig {
        fn bind(&self, n: u8, app: &str) {
            lock(&self.fake.0).capture.push_back(Ok(captured(app)));
            self.mgr.bind(n).unwrap();
            self.mgr.flush();
        }
        fn executed(&self) -> Vec<(u8, String)> {
            lock(&self.fake.0).executed.clone()
        }
        fn last(&self, id: &str) -> DeliveryEvent {
            lock(&self.sink.deliveries).iter().rev().find(|d| d.entry_id == id).cloned().unwrap()
        }
        fn gate(&self) -> (Receiver<()>, Sender<()>) {
            let (e_tx, e_rx) = mpsc::channel();
            let (r_tx, r_rx) = mpsc::channel();
            let mut f = lock(&self.fake.0);
            f.entered = Some(e_tx);
            f.release = Some(r_rx);
            (e_rx, r_tx)
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn entry(id: uuid::Uuid, rev: u32, state: EntryState, text: &str) -> Entry {
        Entry {
            id,
            rev,
            state,
            text: text.into(),
            ts: 0,
            device_id: uuid::Uuid::nil(),
            device_name: "Phone".into(),
            first_received_at: String::new(),
            received_at: String::new(),
            time: "00:00:00".into(),
            partial: state == EntryState::Partial,
            edited: state == EntryState::Edit,
        }
    }

    // ---- tests

    #[test]
    fn bind_also_selects_plays_selected_and_persists() {
        let r = rig();
        r.bind(2, "Teams");
        let v = r.mgr.snapshot();
        assert_eq!(v.active, 2);
        assert_eq!(v.slots.len(), 1);
        assert_eq!(v.slots[0].status, SlotStatus::Live);
        assert_eq!(lock(&r.fake.0).sounds, vec![Sound::Selected]);
        let (stored, warn) = BindingsStore::load(&r.dir);
        assert!(warn.is_none());
        assert_eq!(stored.active().digit(), 2);
    }

    #[test]
    fn bind_refusal_keeps_state_and_notifies() {
        let r = rig();
        lock(&r.fake.0).capture.push_back(Err(InjectError::SecureField));
        r.mgr.bind(1).unwrap();
        lock(&r.fake.0).capture.push_back(Err(InjectError::NotTrusted));
        r.mgr.bind(1).unwrap();
        r.mgr.flush();
        assert_eq!(r.mgr.snapshot().active, 0);
        assert_eq!(lock(&r.fake.0).sounds, vec![Sound::Error, Sound::Error]);
        let n = lock(&r.sink.notices).clone();
        assert_eq!(n[0].code, "bind_failed");
        assert_eq!(n[1].code, "accessibility_needed");
    }

    #[test]
    fn finals_are_delivered_serially_in_fifo_order() {
        let r = rig();
        r.bind(1, "Notes");
        for (i, t) in ["a", "b", "c"].iter().enumerate() {
            r.mgr.on_final(format!("e{i}"), t.to_string());
        }
        r.mgr.flush();
        let texts: Vec<String> = r.executed().into_iter().map(|(_, t)| t).collect();
        assert_eq!(texts, ["a", "b", "c"]);
        let sent: Vec<String> = lock(&r.sink.deliveries)
            .iter()
            .filter(|d| d.status == DeliveryStatus::Sent)
            .map(|d| d.entry_id.clone())
            .collect();
        assert_eq!(sent, ["e0", "e1", "e2"]);
    }

    #[test]
    fn off_delivers_nothing_and_reports_off() {
        let r = rig();
        r.bind(1, "Notes");
        r.mgr.select(0).unwrap();
        r.mgr.on_final("e".into(), "hello".into());
        r.mgr.flush();
        assert!(r.executed().is_empty());
        let d = r.last("e");
        assert_eq!(d.status, DeliveryStatus::Off);
        assert_eq!(d.slot, None);
        assert!(lock(&r.fake.0).sounds.contains(&Sound::Off));
    }

    #[test]
    fn missing_target_is_reported_and_never_falls_back() {
        let r = rig();
        r.bind(1, "Teams");
        lock(&r.fake.0).missing.insert(1);
        r.mgr.on_final("e".into(), "hello".into());
        r.mgr.flush();
        assert!(r.executed().is_empty());
        let d = r.last("e");
        assert_eq!((d.status, d.slot, d.app_name.as_deref()), (DeliveryStatus::Missing, Some(1), Some("Teams")));
        assert_eq!(r.mgr.snapshot().slots[0].status, SlotStatus::Unbound);
    }

    #[test]
    fn blocked_secure_field_secure_input_and_elevated() {
        let r = rig();
        r.bind(1, "Notes");
        let mut c = TargetCaps::from_app("id.Notes", false);
        c.secure_field = true;
        lock(&r.fake.0).caps = Some(c);
        r.mgr.on_final("a".into(), "x".into());
        r.mgr.flush();
        lock(&r.fake.0).caps = None;
        assert_eq!(r.last("a").status, DeliveryStatus::Blocked);
        lock(&r.fake.0).secure_input = true;
        r.mgr.on_final("b".into(), "x".into());
        r.mgr.flush();
        assert_eq!(r.last("b").status, DeliveryStatus::Blocked);
        lock(&r.fake.0).secure_input = false;
        let mut c = TargetCaps::from_app("id.Notes", false);
        c.elevated = true;
        lock(&r.fake.0).caps = Some(c);
        r.mgr.on_final("c".into(), "x".into());
        r.mgr.flush();
        let d = r.last("c");
        assert_eq!(d.status, DeliveryStatus::Blocked);
        assert_eq!(d.reason.as_deref(), Some("target is elevated"));
        assert!(r.executed().is_empty());
    }

    #[test]
    fn focus_changed_is_a_failure_with_its_reason() {
        let r = rig();
        r.bind(1, "Notes");
        lock(&r.fake.0).results.push_back(DeliveryResult::failed("focus changed"));
        r.mgr.on_final("e".into(), "hello".into());
        r.mgr.flush();
        let d = r.last("e");
        assert_eq!(d.status, DeliveryStatus::Failed);
        assert_eq!(d.reason.as_deref(), Some("focus changed"));
        assert_eq!(r.mgr.snapshot().slots[0].status, SlotStatus::Live, "a focus race is not a missing target");
    }

    #[test]
    fn send_to_active_uses_the_current_text_and_refuses_when_off() {
        let r = rig();
        let id = uuid::Uuid::new_v4();
        r.mgr.observe(&HostEvent::EntryUpserted { entry: entry(id, 1, EntryState::Final, "old") });
        assert!(r.mgr.send_to_active(&id.to_string()).is_err(), "Off");
        r.bind(1, "Notes");
        // Block a first delivery so the manual one waits in the queue.
        let (entered, release) = r.gate();
        r.mgr.on_final("first".into(), "x".into());
        entered.recv().unwrap();
        r.mgr.send_to_active(&id.to_string()).unwrap();
        r.mgr.observe(&HostEvent::EntryUpserted { entry: entry(id, 2, EntryState::Edit, "new text") });
        release.send(()).unwrap();
        r.mgr.flush();
        let texts: Vec<String> = r.executed().into_iter().map(|(_, t)| t).collect();
        assert_eq!(texts, ["x", "new text"]);
        assert!(r.last(&id.to_string()).manual);
    }

    #[test]
    fn send_to_active_refuses_partials_and_unknown_entries() {
        let r = rig();
        r.bind(1, "Notes");
        let id = uuid::Uuid::new_v4();
        r.mgr.observe(&HostEvent::EntryUpserted { entry: entry(id, 1, EntryState::Partial, "hel") });
        assert!(r.mgr.send_to_active(&id.to_string()).is_err());
        assert!(r.mgr.send_to_active("nope").is_err());
    }

    #[test]
    fn hotkey_during_delivery_takes_effect_for_the_next_delivery() {
        let r = rig();
        r.bind(1, "Notes");
        r.bind(2, "Teams");
        r.mgr.select(1).unwrap();
        let (entered, release) = r.gate();
        r.mgr.on_final("a".into(), "first".into());
        entered.recv().unwrap();
        r.mgr.select(2).unwrap(); // pressed while "first" is being delivered
        r.mgr.on_final("b".into(), "second".into());
        release.send(()).unwrap();
        r.mgr.flush();
        assert_eq!(r.executed(), vec![(1, "first".into()), (2, "second".into())]);
    }

    #[test]
    fn select_empty_slot_keeps_active_and_plays_empty() {
        let r = rig();
        r.bind(1, "Notes");
        r.mgr.select(5).unwrap();
        r.mgr.flush();
        assert_eq!(r.mgr.snapshot().active, 1);
        assert_eq!(lock(&r.fake.0).sounds.last(), Some(&Sound::Empty));
        assert!(r.mgr.select(10).is_err());
    }

    #[test]
    fn unbind_active_goes_off_and_releases() {
        let r = rig();
        r.bind(3, "Notes");
        r.mgr.unbind(3).unwrap();
        r.mgr.flush();
        let v = r.mgr.snapshot();
        assert_eq!((v.active, v.slots.len()), (0, 0));
        assert!(lock(&r.fake.0).assigned.is_empty());
    }

    #[test]
    fn auto_submit_setting_persists_and_reaches_the_plan() {
        let r = rig();
        r.bind(1, "Notes");
        r.mgr.set_settings(1, Some(true), None).unwrap();
        r.mgr.flush();
        assert!(r.mgr.snapshot().slots[0].auto_submit);
        r.mgr.set_settings(1, None, Some("spaces".into())).unwrap();
        r.mgr.flush();
        assert_eq!(r.mgr.snapshot().slots[0].newline_mode.as_deref(), Some("spaces"));
        let (stored, _) = BindingsStore::load(&r.dir);
        assert!(stored.get(SlotId::new(1).unwrap()).unwrap().settings.auto_submit);
    }

    #[test]
    fn startup_rematch_marks_unverified_until_first_delivery() {
        let dir = tmpdir();
        let mut s = BindingsStore::default();
        s.bind(SlotId::new(1).unwrap(), target("Teams", "chat"));
        s.bind(SlotId::new(2).unwrap(), target("Gone", "x"));
        s.select(1);
        s.save(&dir).unwrap();
        let r = rig_in(dir, |f| {
            f.windows.push(WindowInfo {
                app_id: "id.Teams".into(),
                pid: 7,
                title: "chat".into(),
                standard: true,
                id: 1,
            });
        });
        let v = r.mgr.snapshot();
        assert_eq!(v.active, 1);
        assert_eq!(v.slots[0].status, SlotStatus::Unverified);
        assert_eq!(v.slots[1].status, SlotStatus::Unbound);
        r.mgr.on_final("e".into(), "hi".into());
        r.mgr.flush();
        assert_eq!(r.mgr.snapshot().slots[0].status, SlotStatus::Live);
    }

    #[test]
    fn startup_with_unmatched_active_slot_is_off() {
        let dir = tmpdir();
        let mut s = BindingsStore::default();
        s.bind(SlotId::new(4).unwrap(), target("Gone", "x"));
        s.save(&dir).unwrap();
        let r = rig_in(dir, |_| {});
        assert_eq!(r.mgr.snapshot().active, 0);
        assert_eq!(BindingsStore::load(&r.dir).0.active().digit(), 0);
    }

    #[test]
    fn final_accepted_event_triggers_delivery_once() {
        let r = rig();
        r.bind(1, "Notes");
        let id = uuid::Uuid::new_v4();
        let e = entry(id, 1, EntryState::Final, "dictated");
        r.mgr.observe(&HostEvent::EntryUpserted { entry: e.clone() });
        assert!(r.executed().is_empty(), "an upsert alone never delivers");
        r.mgr.observe(&HostEvent::FinalAccepted { entry: e });
        r.mgr.flush();
        assert_eq!(r.executed(), vec![(1, "dictated".to_string())]);
    }

    #[test]
    fn snapshot_includes_recent_deliveries() {
        let r = rig();
        r.bind(1, "Notes");
        r.mgr.on_final("e".into(), "hi".into());
        r.mgr.flush();
        let v = r.mgr.snapshot();
        assert_eq!(v.deliveries.len(), 1);
        assert_eq!(v.deliveries[0].status, DeliveryStatus::Sent);
    }
}
