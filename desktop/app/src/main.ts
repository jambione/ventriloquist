// Wiring: host events → reducer → DOM. Every peer-provided string (text,
// phone names, error messages) is written with textContent only: it may
// contain control or bidi characters and must never be parsed as HTML.

import "./styles.css";
import { backend } from "./backend";
import { stripBidi } from "./bidi";
import {
  connectionStatus,
  detectPlatform,
  formatCode,
  formatCountdown,
  formatDate,
  isAtBottom,
} from "./format";
import {
  copyText,
  entriesInView,
  initialState,
  onlineDeviceIds,
  reduce,
  visibleEntries,
  type Action,
  type AppState,
} from "./state";
import type { Entry, HostEvent } from "./types";

const COPIED_MS = 1500;
const SNAPSHOT_RETRY_MS = 3000;
const FORGET_CONFIRM_MS = 4000;

function el<T extends HTMLElement = HTMLElement>(id: string): T {
  const e = document.getElementById(id);
  if (e === null) throw new Error(`missing #${id}`);
  return e as T;
}

const dom = {
  header: el("toolbar"),
  main: el("list"),
  statusDot: el("status-dot"),
  statusText: el("status-text"),
  search: el<HTMLInputElement>("search"),
  clearView: el<HTMLButtonElement>("clear-view"),
  openSettings: el<HTMLButtonElement>("open-settings"),
  banners: el("banners"),
  list: el("list"),
  rows: el("rows"),
  empty: el("empty"),
  settings: el("settings"),
  closeSettings: el<HTMLButtonElement>("close-settings"),
  logDir: el("log-dir"),
  configNotSaved: el("config-not-saved"),
  pickLogDir: el<HTMLButtonElement>("pick-log-dir"),
  openLogFolder: el<HTMLButtonElement>("open-log-folder"),
  paired: el<HTMLUListElement>("paired"),
  pairedEmpty: el("paired-empty"),
  nameForm: el<HTMLFormElement>("name-form"),
  nameInput: el<HTMLInputElement>("name-input"),
  pairing: el("pairing"),
  pairingPhone: el("pairing-phone"),
  pairingCode: el("pairing-code"),
  pairingCountdown: el("pairing-countdown"),
  pairingFailed: el("pairing-failed"),
  pairingCancel: el<HTMLButtonElement>("pairing-cancel"),
};

const platform = detectPlatform(navigator.userAgent);
let state: AppState = initialState();
let renderQueued = false;

/** Monotonic clock for every action (pairing deadlines, ticks). */
const now = (): number => performance.now();

function dispatch(action: Action): void {
  const next = reduce(state, action);
  if (next === state) return;
  state = next;
  if (!renderQueued) {
    renderQueued = true;
    requestAnimationFrame(() => {
      renderQueued = false;
      render();
    });
  }
}

function report(what: string, err: unknown): void {
  console.error(what, err);
  dispatch({
    type: "host",
    now: now(),
    event: { event: "storage_warning", message: `${what}: ${String(err)}` },
  });
}

// ------------------------------------------------------------- rendering

interface Row {
  root: HTMLElement;
  time: HTMLElement;
  device: HTMLElement;
  speaking: HTMLElement;
  interrupted: HTMLElement;
  edited: HTMLElement;
  copy: HTMLButtonElement;
  text: HTMLElement;
  shown: Entry | null;
  copyTimer: number | undefined;
}

const rows = new Map<string, Row>();

function span(cls: string, text = ""): HTMLElement {
  const s = document.createElement("span");
  s.className = cls;
  s.textContent = text;
  return s;
}

function makeRow(id: string): Row {
  const root = document.createElement("article");
  root.className = "entry";
  const meta = document.createElement("div");
  meta.className = "meta";
  const time = span("time");
  const device = span("device isolate");
  const speaking = span("badge speaking", "speaking…");
  const interrupted = span("badge interrupted", "interrupted");
  const edited = span("badge edited", "edited");
  const copy = document.createElement("button");
  copy.type = "button";
  copy.className = "copy";
  copy.textContent = "Copy";
  meta.append(time, device, speaking, interrupted, edited, copy);
  const text = document.createElement("div");
  text.className = "text";
  root.append(meta, text);
  const row: Row = {
    root,
    time,
    device,
    speaking,
    interrupted,
    edited,
    copy,
    text,
    shown: null,
    copyTimer: undefined,
  };
  copy.addEventListener("click", () => {
    const e = state.entries.get(id);
    if (e === undefined) return;
    backend.copyText(copyText(e)).then(
      () => flashCopy(row, "Copied ✓"),
      (err: unknown) => {
        console.error("copy failed", err);
        flashCopy(row, "Copy failed");
      },
    );
  });
  return row;
}

function flashCopy(row: Row, label: string): void {
  window.clearTimeout(row.copyTimer);
  row.copy.textContent = label;
  row.copy.classList.add("done");
  row.copyTimer = window.setTimeout(() => {
    row.copy.textContent = "Copy";
    row.copy.classList.remove("done");
  }, COPIED_MS);
}

function updateRow(row: Row, e: Entry): void {
  const old = row.shown;
  if (old === e) return;
  if (old?.time !== e.time) row.time.textContent = e.time;
  if (old?.device_name !== e.device_name) row.device.textContent = stripBidi(e.device_name);
  // Only touch the text when it changed, so a selection survives updates.
  if (old?.text !== e.text) row.text.textContent = e.text;
  const interrupted = e.state === "interrupted";
  row.root.classList.toggle("partial", e.partial);
  row.root.classList.toggle("interrupted", interrupted);
  row.speaking.hidden = !e.partial;
  row.interrupted.hidden = !interrupted;
  row.edited.hidden = !e.edited;
  row.root.setAttribute("aria-busy", e.partial ? "true" : "false");
  row.shown = e;
}

function renderList(): void {
  const atBottom = isAtBottom(
    dom.list.scrollTop,
    dom.list.scrollHeight,
    dom.list.clientHeight,
  );
  const visible = visibleEntries(state);
  const keep = new Set<string>();
  let cursor: ChildNode | null = dom.rows.firstChild;
  for (const e of visible) {
    keep.add(e.id);
    let row = rows.get(e.id);
    if (row === undefined) {
      row = makeRow(e.id);
      rows.set(e.id, row);
    }
    updateRow(row, e);
    if (row.root === cursor) {
      cursor = cursor.nextSibling;
    } else {
      dom.rows.insertBefore(row.root, cursor);
    }
  }
  for (const [id, row] of rows) {
    if (!keep.has(id)) {
      window.clearTimeout(row.copyTimer);
      row.root.remove();
      rows.delete(id);
    }
  }
  if (visible.length === 0) {
    dom.empty.hidden = false;
    dom.empty.textContent =
      state.search !== "" && entriesInView(state) > 0
        ? "No entries match the search."
        : "Dictate on your iPhone — the text appears here.";
  } else {
    dom.empty.hidden = true;
  }
  if (atBottom) dom.list.scrollTop = dom.list.scrollHeight;
}

function renderStatus(): void {
  const s = connectionStatus(state, platform);
  dom.statusDot.className = `dot ${s.tone}`;
  dom.statusText.textContent = s.text;
}

function banner(kind: string, text: string, onDismiss: (() => void) | null): HTMLElement {
  const b = document.createElement("div");
  b.className = `banner ${kind}`;
  b.setAttribute("role", kind === "error" ? "alert" : "status");
  const t = document.createElement("span");
  t.className = "banner-text";
  t.textContent = text;
  b.append(t);
  if (onDismiss !== null) {
    const x = document.createElement("button");
    x.type = "button";
    x.className = "icon";
    x.setAttribute("aria-label", "Dismiss");
    x.textContent = "✕";
    x.addEventListener("click", onDismiss);
    b.append(x);
  }
  return b;
}

let bannersShown: readonly unknown[] = [];

function renderBanners(): void {
  const key = [state.fatal, state.logWarning, state.notices];
  if (key.every((v, i) => v === bannersShown[i])) return;
  bannersShown = key;
  const items: HTMLElement[] = [];
  if (state.fatal !== null) {
    items.push(banner("error", `Ventriloquist could not start: ${state.fatal}`, null));
  }
  if (state.logWarning !== null) {
    items.push(
      banner(
        "warn",
        `The log file could not be written (transcription continues; it will retry): ${state.logWarning}`,
        null,
      ),
    );
  }
  for (const n of state.notices) {
    items.push(
      banner(n.kind === "storage" ? "warn" : "info", n.text, () =>
        dispatch({ type: "dismiss_notice", id: n.id }),
      ),
    );
  }
  dom.banners.replaceChildren(...items);
}

const forgetArmed = new Map<string, number>();

let settingsShown: readonly unknown[] = [];

function renderSettings(force = false): void {
  const key = [state.logDir, state.configPersisted, state.name, state.pairedPeers, state.peers];
  if (!force && key.every((v, i) => v === settingsShown[i])) return;
  settingsShown = key;
  dom.logDir.textContent = state.logDir;
  dom.configNotSaved.hidden = state.configPersisted;
  if (document.activeElement !== dom.nameInput && dom.nameInput.value !== state.name) {
    dom.nameInput.value = state.name;
  }
  const online = onlineDeviceIds(state);
  const items: HTMLElement[] = [];
  for (const p of state.pairedPeers) {
    const li = document.createElement("li");
    const info = document.createElement("div");
    info.className = "peer-info";
    const name = span("peer-name isolate", stripBidi(p.name));
    const meta = span("muted", `paired ${formatDate(p.paired_at_ms)}`);
    info.append(name, meta);
    if (online.has(p.device_id)) info.append(span("badge online", "connected"));
    const forget = document.createElement("button");
    forget.type = "button";
    forget.className = "danger";
    const armed = forgetArmed.has(p.device_id);
    forget.textContent = armed ? "Really forget?" : "Forget";
    forget.addEventListener("click", () => onForget(p.device_id));
    li.append(info, forget);
    items.push(li);
  }
  dom.paired.replaceChildren(...items);
  dom.pairedEmpty.hidden = state.pairedPeers.length > 0;
}

function onForget(deviceId: string): void {
  if (forgetArmed.has(deviceId)) {
    window.clearTimeout(forgetArmed.get(deviceId));
    forgetArmed.delete(deviceId);
    backend.forgetPeer(deviceId).catch((e: unknown) => report("Could not forget the phone", e));
  } else {
    forgetArmed.set(
      deviceId,
      window.setTimeout(() => {
        forgetArmed.delete(deviceId);
        renderSettings(true);
      }, FORGET_CONFIRM_MS),
    );
  }
  renderSettings(true);
}

let pairingTimer: number | undefined;

function renderPairing(): void {
  const p = state.pairing;
  if (p === null) {
    dom.pairing.hidden = true;
    window.clearInterval(pairingTimer);
    pairingTimer = undefined;
    return;
  }
  const wasHidden = dom.pairing.hidden;
  dom.pairing.hidden = false;
  dom.pairingPhone.textContent = stripBidi(p.phoneName);
  dom.pairingCode.textContent = formatCode(p.code);
  dom.pairingCountdown.textContent = formatCountdown(p.deadline - now());
  if (p.attemptsRemaining === null) {
    dom.pairingFailed.hidden = true;
  } else {
    dom.pairingFailed.hidden = false;
    dom.pairingFailed.textContent = `Wrong code entered on the phone — ${p.attemptsRemaining} ${
      p.attemptsRemaining === 1 ? "attempt" : "attempts"
    } left.`;
  }
  if (pairingTimer === undefined) {
    pairingTimer = window.setInterval(() => {
      dispatch({ type: "tick", now: now() });
      if (state.pairing !== null) {
        dom.pairingCountdown.textContent = formatCountdown(state.pairing.deadline - now());
      }
    }, 250);
  }
  if (wasHidden) dom.pairingCancel.focus();
}

function render(): void {
  renderStatus();
  renderBanners();
  renderList();
  renderSettings();
  renderPairing();
  dom.clearView.disabled = entriesInView(state) === 0;
  updateInert();
}

// ---------------------------------------------------------------- inputs

dom.search.addEventListener("input", () => dispatch({ type: "search", query: dom.search.value }));
dom.clearView.addEventListener("click", () => dispatch({ type: "clear_view" }));

/** While a dialog is open the page behind it is inert: Tab cannot leave
 * the dialog and Cmd/Ctrl+F cannot focus the hidden search field. */
function updateInert(): void {
  const modal = !dom.settings.hidden || state.pairing !== null;
  for (const e of [dom.header, dom.banners, dom.main]) e.inert = modal;
  dom.settings.inert = state.pairing !== null;
}

function openSettings(): void {
  dom.settings.hidden = false;
  updateInert();
  renderSettings(true);
  dom.closeSettings.focus();
}
function closeSettings(): void {
  dom.settings.hidden = true;
  updateInert();
  dom.openSettings.focus();
}
dom.openSettings.addEventListener("click", openSettings);
dom.closeSettings.addEventListener("click", closeSettings);
dom.settings.addEventListener("click", (e) => {
  if (e.target === dom.settings) closeSettings();
});

dom.pickLogDir.addEventListener("click", () => {
  // One picker at a time (the host sets the folder itself).
  if (dom.pickLogDir.disabled) return;
  dom.pickLogDir.disabled = true;
  backend
    .pickLogDir()
    .catch((e: unknown) => report("Could not change the log folder", e))
    .finally(() => {
      dom.pickLogDir.disabled = false;
    });
});
dom.openLogFolder.addEventListener("click", () => {
  backend.openLogFolder().catch((e: unknown) => report("Could not open the log folder", e));
});
dom.nameForm.addEventListener("submit", (e) => {
  e.preventDefault();
  backend.setName(dom.nameInput.value).catch((err: unknown) => report("Could not save the name", err));
  dom.nameInput.blur();
});

function cancelPairing(): void {
  const p = state.pairing;
  if (p === null) return;
  dispatch({ type: "dismiss_pairing" });
  backend.cancelPairing(p.peer).catch((e: unknown) => report("Could not cancel pairing", e));
}
dom.pairingCancel.addEventListener("click", cancelPairing);

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    if (state.pairing !== null) cancelPairing();
    else if (!dom.settings.hidden) closeSettings();
    else if (document.activeElement === dom.search && dom.search.value !== "") {
      dom.search.value = "";
      dispatch({ type: "search", query: "" });
    }
  } else if (e.key.toLowerCase() === "f" && (e.metaKey || e.ctrlKey)) {
    e.preventDefault();
    if (!dom.settings.hidden || state.pairing !== null) return;
    dom.search.focus();
    dom.search.select();
  }
});

// ---------------------------------------------------------------- start

/** Events handled but not yet acknowledged to the host (flow control). */
let unacked = 0;
let ackTimer: number | undefined;
const ACK_EVERY = 16;
const ACK_DELAY_MS = 100;

function flushAcks(): void {
  window.clearTimeout(ackTimer);
  ackTimer = undefined;
  const n = unacked;
  unacked = 0;
  if (n > 0) backend.ackEvents(n).catch((e: unknown) => console.error("ack failed", e));
}

function onHostEvent(event: HostEvent): void {
  dispatch({ type: "host", event, now: now() });
  // Acknowledge from a timer, not the render loop: rAF is paused while the
  // window is hidden.
  unacked++;
  if (unacked >= ACK_EVERY) flushAcks();
  else ackTimer ??= window.setTimeout(flushAcks, ACK_DELAY_MS);
}

/** Unanswered snapshot requests after which the user is told. */
const SNAPSHOT_TRIES_BEFORE_NOTICE = 10;

async function start(): Promise<void> {
  // Subscribe first, then ask for the snapshot: events that arrive before
  // its reply are buffered by the reducer. A lost or undeliverable
  // snapshot is requested again until one arrives.
  await backend.onHostEvent(onHostEvent);
  let tries = 0;
  const ask = (): void => {
    if (state.phase !== "loading") return;
    tries++;
    if (tries === SNAPSHOT_TRIES_BEFORE_NOTICE) {
      report("The host is not answering", "still waiting for its state");
    }
    backend.snapshot().then(
      () => window.setTimeout(ask, SNAPSHOT_RETRY_MS),
      (e: unknown) => dispatch({ type: "fatal", message: String(e) }),
    );
  };
  ask();
}

render();
start().catch((e: unknown) => dispatch({ type: "fatal", message: String(e) }));
