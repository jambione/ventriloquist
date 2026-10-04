// Wiring: host events → reducer → DOM. Every peer-provided string (text,
// phone names, error messages) is written with textContent only: it may
// contain control or bidi characters and must never be parsed as HTML.

import "./styles.css";
import { backend } from "./backend";
import { stripBidi } from "./bidi";
import {
  canSendToActive,
  connectionStatus,
  deliveryBadge,
  formatHotkey,
  modifierChoices,
  slotChips,
  takenText,
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
import type { Entry, HostEvent, Modifier, NewlineMode, SlotView } from "./types";

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
  slotbar: el("slotbar"),
  chips: el("chips"),
  axNeeded: el("ax-needed"),
  axOpenBar: el<HTMLButtonElement>("ax-open-bar"),
  slotMenu: el("slot-menu"),
  axRow: el("ax-row"),
  axStatus: el("ax-status"),
  axOpen: el<HTMLButtonElement>("ax-open"),
  modsSelect: el<HTMLFieldSetElement>("mods-select"),
  modsBind: el<HTMLFieldSetElement>("mods-bind"),
  boundSlots: el<HTMLUListElement>("bound-slots"),
  boundEmpty: el("bound-empty"),
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
  delivery: HTMLElement;
  send: HTMLButtonElement;
  copy: HTMLButtonElement;
  text: HTMLElement;
  shown: Entry | null;
  shownDelivery: unknown;
  shownActive: number;
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
  const delivery = span("badge delivery");
  delivery.hidden = true;
  const send = document.createElement("button");
  send.type = "button";
  send.className = "send";
  send.textContent = "Send to active slot";
  const copy = document.createElement("button");
  copy.type = "button";
  copy.className = "copy";
  copy.textContent = "Copy";
  meta.append(time, device, speaking, interrupted, edited, delivery, send, copy);
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
    delivery,
    send,
    copy,
    text,
    shown: null,
    shownDelivery: undefined,
    shownActive: -1,
    copyTimer: undefined,
  };
  send.addEventListener("click", () => {
    backend.sendToActive(id).catch((err: unknown) => report("Could not send to the active slot", err));
  });
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
  const d = state.deliveries.get(e.id);
  const active = state.slots?.active ?? 0;
  if (row.shownDelivery !== d || row.shownActive !== active || old?.state !== e.state) {
    const badge = deliveryBadge(d);
    row.delivery.hidden = badge === null;
    if (badge !== null) {
      row.delivery.textContent = badge.text;
      row.delivery.className = `badge delivery ${badge.tone}`;
    }
    row.send.disabled = !canSendToActive(state.slots, e.state);
    row.shownDelivery = d;
    row.shownActive = active;
  }
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
  const key = [
    state.logDir,
    state.configPersisted,
    state.name,
    state.pairedPeers,
    state.peers,
    state.slots,
    state.accessibility,
  ];
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
  renderBindingsSettings();
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

// ---------------------------------------------------------- slot bar

let slotsRendered: unknown;
let menuSlot: number | null = null;

function renderSlotBar(): void {
  const ax = state.accessibility;
  const axNeeded = ax !== null && ax.supported && !ax.trusted;
  dom.axNeeded.hidden = !axNeeded;
  if (slotsRendered !== state.slots) {
    slotsRendered = state.slots;
    const items: HTMLElement[] = [];
    for (const c of slotChips(state.slots)) {
      const wrap = document.createElement("span");
      wrap.className = "chip";
      if (!c.bound) wrap.classList.add("vacant"); // not "empty": that class is the list placeholder (20vh margin)
      if (c.unbound) wrap.classList.add("unbound");
      if (c.active) wrap.classList.add("active");
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = c.label; // app and title are other apps' strings
      b.title = c.tooltip;
      b.setAttribute("aria-pressed", c.active ? "true" : "false");
      b.addEventListener("click", () => {
        backend.selectSlot(c.slot).catch((e: unknown) => report("Could not select the slot", e));
      });
      wrap.append(b);
      if (c.unbound) b.append(span("mark", " rebind"));
      if (c.unverified) b.append(span("mark", " ?"));
      if (c.autoSubmit) b.append(span("mark", " ⏎"));
      if (c.slot > 0 && c.bound) {
        const more = document.createElement("button");
        more.type = "button";
        more.className = "more";
        more.textContent = "⋯";
        more.setAttribute("aria-label", `Slot ${c.slot} options`);
        more.addEventListener("click", (ev) => {
          ev.stopPropagation();
          if (menuSlot === c.slot) closeMenu();
          else openMenu(c.slot, more);
        });
        wrap.append(more);
      }
      items.push(wrap);
    }
    dom.chips.replaceChildren(...items);
    if (menuSlot !== null) renderMenu();
  }
}

function slotView(n: number): SlotView | undefined {
  return state.slots?.slots.find((s) => s.slot === n);
}

function openMenu(n: number, anchor: HTMLElement): void {
  menuSlot = n;
  const r = anchor.getBoundingClientRect();
  dom.slotMenu.style.top = `${Math.round(r.bottom + 4)}px`;
  dom.slotMenu.style.left = `${Math.max(4, Math.round(Math.min(r.left, window.innerWidth - 230)))}px`;
  dom.slotMenu.hidden = false;
  renderMenu();
}

function closeMenu(): void {
  menuSlot = null;
  dom.slotMenu.hidden = true;
}

function renderMenu(): void {
  const s = menuSlot === null ? undefined : slotView(menuSlot);
  if (s === undefined) {
    closeMenu();
    return;
  }
  const n = s.slot;
  const auto = document.createElement("label");
  const cb = document.createElement("input");
  cb.type = "checkbox";
  cb.checked = s.auto_submit;
  cb.addEventListener("change", () => {
    backend
      .setSlotSettings(n, { autoSubmit: cb.checked })
      .catch((e: unknown) => report("Could not change auto-submit", e));
  });
  auto.append(cb, document.createTextNode("Auto-submit (Enter)"));
  const items: HTMLElement[] = [auto];
  if (s.newline_mode !== null) {
    const lab = document.createElement("label");
    const sel = document.createElement("select");
    for (const [v, t] of [
      ["shift_enter", "Shift+Enter"],
      ["spaces", "Spaces"],
    ] as const) {
      const o = document.createElement("option");
      o.value = v;
      o.textContent = t;
      sel.append(o);
    }
    sel.value = s.newline_mode;
    sel.addEventListener("change", () => {
      backend
        .setSlotSettings(n, { newlineMode: sel.value as NewlineMode })
        .catch((e: unknown) => report("Could not change the newline mode", e));
    });
    lab.append(document.createTextNode("Newline mode "), sel);
    items.push(lab);
  }
  const follow = document.createElement("label");
  follow.title =
    "Off: text is only sent while the window's title is exactly what it was when you bound the slot " +
    "(so a chat or tab switch in the same window is never typed into). Rebinding updates the title.";
  const fcb = document.createElement("input");
  fcb.type = "checkbox";
  fcb.checked = s.follow_title_changes;
  fcb.addEventListener("change", () => {
    backend
      .setSlotSettings(n, { followTitleChanges: fcb.checked })
      .catch((e: unknown) => report("Could not change the setting", e));
  });
  follow.append(fcb, document.createTextNode("Follow window when its title changes"));
  items.push(follow);
  const unbind = document.createElement("button");
  unbind.type = "button";
  unbind.className = "danger";
  unbind.textContent = "Unbind";
  unbind.addEventListener("click", () => {
    closeMenu();
    backend.unbindSlot(n).catch((e: unknown) => report("Could not unbind the slot", e));
  });
  items.push(unbind);
  dom.slotMenu.replaceChildren(...items);
}

document.addEventListener("click", (e) => {
  if (menuSlot !== null && !dom.slotMenu.contains(e.target as Node)) closeMenu();
});

dom.axOpenBar.addEventListener("click", openAccessibility);
dom.axOpen.addEventListener("click", openAccessibility);
function openAccessibility(): void {
  backend
    .openAccessibilitySettings()
    .catch((e: unknown) => report("Could not open System Settings", e));
}

function refreshAccessibility(): void {
  if (platform === "windows") return;
  backend.accessibilityStatus().then(
    (status) => dispatch({ type: "accessibility", status }),
    (e: unknown) => console.error("accessibility status failed", e),
  );
}

/** Settings → Bindings: permission, hotkey modifier pickers, slot list. */
function renderBindingsSettings(): void {
  const ax = state.accessibility;
  const showAx = platform !== "windows" && ax !== null && ax.supported;
  dom.axRow.hidden = !showAx;
  if (showAx) dom.axStatus.textContent = ax.trusted ? "granted" : "not granted";

  const hk = state.slots?.hotkeys;
  if (hk !== undefined) {
    renderMods(dom.modsSelect, "select", "Select slot", hk.select, "0–9", hk.select_taken);
    renderMods(dom.modsBind, "bind", "Bind slot", hk.bind, "1–9", hk.bind_taken);
  }

  const items: HTMLElement[] = [];
  for (const s of state.slots?.slots ?? []) {
    const li = document.createElement("li");
    const info = document.createElement("div");
    info.className = "peer-info";
    const name = span("peer-name isolate", `${s.slot} · ${stripBidi(s.app_name)}`);
    info.append(name, span("muted isolate", stripBidi(s.window_title)));
    const unbind = document.createElement("button");
    unbind.type = "button";
    unbind.className = "danger";
    unbind.textContent = "Unbind";
    unbind.addEventListener("click", () => {
      backend.unbindSlot(s.slot).catch((e: unknown) => report("Could not unbind the slot", e));
    });
    li.append(info, unbind);
    items.push(li);
  }
  dom.boundSlots.replaceChildren(...items);
  dom.boundEmpty.hidden = items.length > 0;
}

function renderMods(
  box: HTMLFieldSetElement,
  kind: "select" | "bind",
  title: string,
  mods: readonly Modifier[],
  range: string,
  taken: readonly number[],
): void {
  const legend = document.createElement("legend");
  legend.textContent = `${title}: ${formatHotkey(mods, range, platform)}`;
  const items: HTMLElement[] = [legend];
  for (const c of modifierChoices(platform)) {
    const lab = document.createElement("label");
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = mods.includes(c.mod);
    cb.addEventListener("change", () => {
      const next = modifierChoices(platform)
        .filter((x) => (x.mod === c.mod ? cb.checked : mods.includes(x.mod)))
        .map((x) => x.mod);
      backend.setHotkeyModifiers(kind, next).then(
        () => undefined,
        (e: unknown) => {
          report("Could not change the hotkey", e);
          renderSettings(true); // put the checkboxes back
        },
      );
    });
    lab.append(cb, document.createTextNode(c.label));
    items.push(lab);
  }
  const t = takenText(taken);
  if (t !== "") items.push(span("taken warn-text", t));
  box.replaceChildren(...items);
}


function render(): void {
  renderSlotBar();
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
  for (const e of [dom.header, dom.slotbar, dom.banners, dom.main]) e.inert = modal;
  dom.settings.inert = state.pairing !== null;
}

function openSettings(): void {
  dom.settings.hidden = false;
  refreshAccessibility();
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
    if (menuSlot !== null) closeMenu();
    else if (state.pairing !== null) cancelPairing();
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
  await backend.onSlots((view) => dispatch({ type: "slots", view }));
  await backend.onDelivery((event) => dispatch({ type: "delivery", event }));
  await backend.onBindingNotice((notice) => dispatch({ type: "binding_notice", notice }));
  backend.slotsSnapshot().then(
    (view) => dispatch({ type: "slots_snapshot", view }),
    (e: unknown) => console.error("slots snapshot failed", e),
  );
  refreshAccessibility();
  window.addEventListener("focus", refreshAccessibility);
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
