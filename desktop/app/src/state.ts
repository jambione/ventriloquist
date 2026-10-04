// UI state and its reducer. Pure: no DOM, no Tauri, no clock (the time
// is passed in with each action), so it is unit-tested in Node.
//
// Load protocol (desktop/core/README.md, D11): the page subscribes to host
// events, then asks for a `snapshot`. Until the snapshot arrives, events
// are buffered. The snapshot is authoritative; the buffered events are then
// merged where the host's coalescing outbox may have delivered a *newer*
// event ahead of the snapshot (a partial, or a pairing code, replaced in
// place in the queue), and the non-state events (warnings, notices) are
// replayed. Any later snapshot (e.g. a reply meant for a previous page
// load) is applied the same way.

import { clip, isolate, stripBidi } from "./bidi";
import type {
  AccessibilityStatus,
  AdapterState,
  BindingNotice,
  DeliveryEvent,
  Entry,
  HostEvent,
  PairedPeer,
  PeerState,
  SlotsView,
} from "./types";

/** In-memory history cap (SPEC §6.1); the core enforces it too. */
export const MAX_ENTRIES = 500;
/** Pre-snapshot events kept; older ones are dropped (the snapshot covers them). */
export const MAX_BUFFERED = 2000;
/** Dismissible notices kept on screen. */
export const MAX_NOTICES = 5;
/** Longest peer-provided message shown in a notice (characters). */
export const MAX_NOTICE_TEXT = 200;
/** Evicted ids remembered (id → highest rev), mirroring the core (A3). */
export const MAX_TOMBSTONES = 10_000;
/** Pairing codes kept at once (one per connection; the newest is shown). */
export const MAX_CODES = 8;
/** Delivery results remembered (per entry id). */
export const MAX_DELIVERIES = 500;
/** Longest accepted code lifetime; the core uses 120 s. */
const MAX_CODE_SECS = 3600;
const DEFAULT_CODE_SECS = 120;

/** Monotonic milliseconds (unaffected by wall-clock changes). Pairing
 * deadlines live in this domain: `tick` actions must carry the same clock. */
export function mono(): number {
  return performance.now();
}

/** Lifetime of a code in ms: invalid (NaN, infinite, negative) → 0 (already
 * expired); longer than an hour → the default of 120 s. */
function codeLifetimeMs(secs: number): number {
  if (!Number.isFinite(secs) || secs < 0) return 0;
  return (secs > MAX_CODE_SECS ? DEFAULT_CODE_SECS : secs) * 1000;
}

export interface PeerInfo {
  peer: string;
  state: PeerState;
  device_id: string | null;
  name: string | null;
  paired: boolean;
}

export interface PairingModal {
  peer: string;
  phoneName: string;
  /** Exactly 6 ASCII digits. */
  code: string;
  /** Expiry, ms since the epoch (local clock). */
  deadline: number;
  /** Set after a wrong code was entered on the phone. */
  attemptsRemaining: number | null;
}

export type NoticeKind = "storage" | "peer" | "version" | "binding";

export interface Notice {
  id: number;
  kind: NoticeKind;
  text: string;
}

interface Buffered {
  event: HostEvent;
  at: number;
}

export interface AppState {
  phase: "loading" | "ready" | "fatal";
  fatal: string | null;
  buffered: Buffered[];
  deviceId: string | null;
  name: string;
  logDir: string;
  /** False after a `config_changed` whose save failed. */
  configPersisted: boolean;
  pairedPeers: PairedPeer[];
  adapter: AdapterState;
  /** Live connections (closed ones are removed). */
  peers: ReadonlyMap<string, PeerInfo>;
  entries: ReadonlyMap<string, Entry>;
  /** Entry ids, oldest first (order of first arrival). */
  order: readonly string[];
  /** Clear view: id → highest rev hidden. A later revision shows it again. */
  cleared: ReadonlyMap<string, number>;
  /** Evicted ids → highest rev seen (bounded, insertion-ordered). It is
   * append-only, so it is shared (mutated in place) between state versions
   * to keep eviction O(1). Upserts at or below it are ignored. */
  evicted: ReadonlyMap<string, number>;
  search: string;
  /** The code on screen: the newest of `codes`. */
  pairing: PairingModal | null;
  /** Every still-valid code, oldest first (one per connection). */
  codes: readonly PairingModal[];
  logWarning: string | null;
  notices: readonly Notice[];
  nextNoticeId: number;
  /** Slot bar state; null until the first `slots` event or snapshot. */
  slots: SlotsView | null;
  /** Latest delivery result per entry id (insertion-ordered, bounded). */
  deliveries: ReadonlyMap<string, DeliveryEvent>;
  /** Accessibility permission; null until known. */
  accessibility: AccessibilityStatus | null;
}

export type Action =
  | { type: "host"; event: HostEvent; now: number }
  | { type: "search"; query: string }
  | { type: "clear_view" }
  | { type: "tick"; now: number }
  | { type: "dismiss_pairing" }
  | { type: "dismiss_notice"; id: number }
  | { type: "fatal"; message: string }
  /** A `slots` event: the whole slot bar. */
  | { type: "slots"; view: SlotsView }
  /** The reply to `slots_snapshot` (also carries recent deliveries). */
  | { type: "slots_snapshot"; view: SlotsView }
  | { type: "delivery"; event: DeliveryEvent }
  | { type: "binding_notice"; notice: BindingNotice }
  | { type: "accessibility"; status: AccessibilityStatus };

export function initialState(): AppState {
  return {
    phase: "loading",
    fatal: null,
    buffered: [],
    deviceId: null,
    name: "",
    logDir: "",
    configPersisted: true,
    pairedPeers: [],
    adapter: "unknown",
    peers: new Map(),
    entries: new Map(),
    order: [],
    cleared: new Map(),
    evicted: new Map(),
    search: "",
    pairing: null,
    codes: [],
    logWarning: null,
    notices: [],
    nextNoticeId: 1,
    slots: null,
    deliveries: new Map(),
    accessibility: null,
  };
}

export function reduce(state: AppState, action: Action): AppState {
  switch (action.type) {
    case "host":
      return onHostEvent(state, action.event, action.now);
    case "search":
      return state.search === action.query ? state : { ...state, search: action.query };
    case "clear_view":
      return clearView(state);
    case "tick":
      return state.codes.some((c) => action.now >= c.deadline)
        ? withCodes(
            state,
            state.codes.filter((c) => action.now < c.deadline),
          )
        : state;
    case "dismiss_pairing": {
      const shown = state.pairing;
      return shown === null ? state : withCodes(state, withoutPeer(state.codes, shown.peer));
    }
    case "dismiss_notice":
      return { ...state, notices: state.notices.filter((n) => n.id !== action.id) };
    case "fatal":
      return { ...state, phase: "fatal", fatal: action.message, buffered: [] };
    case "slots":
      return { ...state, slots: withoutDeliveries(action.view) };
    case "slots_snapshot":
      return onSlotsSnapshot(state, action.view);
    case "delivery":
      return onDelivery(state, action.event);
    case "binding_notice":
      return onBindingNotice(state, action.notice);
    case "accessibility":
      return state.accessibility?.supported === action.status.supported &&
        state.accessibility?.trusted === action.status.trusted
        ? state
        : { ...state, accessibility: action.status };
  }
}

// -------------------------------------------------------------- bindings

function withoutDeliveries(v: SlotsView): SlotsView {
  return { active: v.active, slots: v.slots, hotkeys: v.hotkeys };
}

function putDelivery(
  map: ReadonlyMap<string, DeliveryEvent>,
  ev: DeliveryEvent,
): Map<string, DeliveryEvent> {
  const m = new Map(map);
  m.delete(ev.entry_id); // refresh the insertion order
  m.set(ev.entry_id, ev);
  while (m.size > MAX_DELIVERIES) {
    const oldest = m.keys().next();
    if (oldest.done === true) break;
    m.delete(oldest.value);
  }
  return m;
}

function onDelivery(state: AppState, ev: DeliveryEvent): AppState {
  let next: AppState = { ...state, deliveries: putDelivery(state.deliveries, ev) };
  if (ev.status === "missing") {
    const slot = ev.slot === null ? "" : `Slot ${ev.slot} `;
    const app = ev.app_name === null ? "" : `(${isolate(clip(ev.app_name, MAX_LABEL_CHARS))}) `;
    next = addBindingNotice(next, `${slot}${app}not found — not sent`);
  }
  return next;
}

function onSlotsSnapshot(state: AppState, view: SlotsView): AppState {
  let deliveries = state.deliveries;
  for (const d of view.deliveries ?? []) {
    const have = deliveries.get(d.entry_id);
    // A live event may be newer than the snapshot: never go back to
    // "sending" from a result.
    if (have !== undefined && have.status !== "sending" && d.status === "sending") continue;
    deliveries = putDelivery(deliveries, d);
  }
  return { ...state, slots: withoutDeliveries(view), deliveries };
}

/** Add a binding notice unless it repeats the newest one. */
function addBindingNotice(state: AppState, text: string): AppState {
  const last = state.notices[state.notices.length - 1];
  if (last !== undefined && last.kind === "binding" && last.text === text) return state;
  return addNotice(state, "binding", text);
}

function onBindingNotice(state: AppState, n: BindingNotice): AppState {
  const slot = n.slot === null ? "" : `Slot ${n.slot}: `;
  const detail = n.detail === null ? "" : isolate(clip(n.detail, MAX_NOTICE_TEXT));
  switch (n.code) {
    case "accessibility_needed":
      return addBindingNotice(
        {
          ...state,
          accessibility: { supported: true, trusted: false },
        },
        `${slot}Accessibility permission needed — allow Ventriloquist in System Settings › Privacy & Security › Accessibility.`,
      );
    case "bind_failed":
      return addBindingNotice(state, `${slot}not bound: ${detail}`);
    case "save_failed":
      return addBindingNotice(state, `Could not save the bindings: ${detail}`);
    case "bindings_warning":
      return addBindingNotice(state, detail);
  }
}

// ---------------------------------------------------------------- events

function onHostEvent(state: AppState, ev: HostEvent, now: number): AppState {
  if (ev.event === "snapshot") {
    return applySnapshot(state, ev, now);
  }
  if (state.phase === "loading") {
    const buffered = [...state.buffered, { event: ev, at: mono() }];
    if (buffered.length > MAX_BUFFERED) buffered.splice(0, buffered.length - MAX_BUFFERED);
    return { ...state, buffered };
  }
  return applyEvent(state, ev, now);
}

/** Whether `incoming` replaces `existing` (highest rev wins; a partial may
 * turn `interrupted` at the same rev, D8). */
export function accepts(existing: Entry | undefined, incoming: Entry): boolean {
  if (existing === undefined) return true;
  if (incoming.rev > existing.rev) return true;
  return (
    incoming.rev === existing.rev &&
    incoming.state === "interrupted" &&
    existing.state === "partial"
  );
}

function upsertEntry(state: AppState, entry: Entry): AppState {
  const existing = state.entries.get(entry.id);
  if (!accepts(existing, entry)) return state;
  const tomb = state.evicted.get(entry.id);
  if (tomb !== undefined && entry.rev <= tomb) return state;
  const entries = new Map(state.entries);
  entries.set(entry.id, entry);
  let order = state.order;
  let cleared = state.cleared;
  if (existing === undefined) {
    const next = [...order, entry.id];
    if (next.length > MAX_ENTRIES) {
      const gone = next.splice(0, next.length - MAX_ENTRIES);
      const c = new Map(cleared);
      for (const id of gone) {
        const rev = entries.get(id)?.rev;
        if (rev !== undefined) tombstone(state.evicted, id, rev);
        entries.delete(id);
        c.delete(id);
      }
      cleared = c;
    }
    order = next;
  }
  return { ...state, entries, order, cleared };
}

/** Remember `id` as evicted at `rev` (never lowering a known rev). */
function tombstone(map: ReadonlyMap<string, number>, id: string, rev: number): void {
  const m = map as Map<string, number>;
  const rev2 = Math.max(rev, m.get(id) ?? -1);
  m.delete(id); // refresh the insertion order
  m.set(id, rev2);
  if (m.size > MAX_TOMBSTONES) {
    const oldest = m.keys().next();
    if (oldest.done !== true) m.delete(oldest.value);
  }
}

function evictEntry(state: AppState, id: string): AppState {
  const existing = state.entries.get(id);
  tombstone(state.evicted, id, existing?.rev ?? -1);
  if (existing === undefined) return state;
  const entries = new Map(state.entries);
  entries.delete(id);
  const cleared = new Map(state.cleared);
  cleared.delete(id);
  return { ...state, entries, cleared, order: state.order.filter((x) => x !== id) };
}

/** `text` is already bounded and its peer-provided parts isolated. */
function addNotice(state: AppState, kind: NoticeKind, text: string): AppState {
  const notice: Notice = { id: state.nextNoticeId, kind, text };
  const notices = [...state.notices, notice].slice(-MAX_NOTICES);
  return { ...state, notices, nextNoticeId: state.nextNoticeId + 1 };
}

const MAX_LABEL_CHARS = 64;

/** A peer's name for a sentence: clipped, bidi-stripped, isolated. */
function peerLabel(state: AppState, peer: string): string {
  const name = state.peers.get(peer)?.name;
  return name === null || name === undefined ? "a phone" : isolate(clip(name, MAX_LABEL_CHARS));
}

function applyEvent(state: AppState, ev: HostEvent, now: number): AppState {
  switch (ev.event) {
    case "snapshot":
      return applySnapshot(state, ev, now);
    case "started":
      return {
        ...state,
        deviceId: ev.device_id,
        name: ev.name,
        logDir: ev.log_dir,
        pairedPeers: ev.paired_peers,
      };
    case "entry_upserted":
      return upsertEntry(state, ev.entry);
    case "entry_evicted":
      return evictEntry(state, ev.id);
    case "connection_status": {
      const peers = new Map(state.peers);
      if (ev.state === "closed") {
        peers.delete(ev.peer);
      } else {
        peers.set(ev.peer, {
          peer: ev.peer,
          state: ev.state,
          device_id: ev.device_id,
          name: ev.name,
          paired: ev.paired,
        });
      }
      const next = { ...state, peers };
      return ev.state === "closed" ? withCodes(next, withoutPeer(state.codes, ev.peer)) : next;
    }
    case "pairing_code_shown": {
      const rest = withoutPeer(state.codes, ev.peer);
      const ms = codeLifetimeMs(ev.expires_in_secs);
      if (ms <= 0) return withCodes(state, rest); // already expired
      return withCodes(state, [
        ...rest,
        {
          peer: ev.peer,
          phoneName: stripBidi(ev.phone_name),
          code: ev.code,
          deadline: mono() + ms,
          attemptsRemaining: null,
        },
      ]);
    }
    case "pairing_code_ended":
      return withCodes(state, withoutPeer(state.codes, ev.peer));
    case "pairing_result": {
      const code = state.codes.find((c) => c.peer === ev.peer);
      if (code === undefined) return state;
      // A wrong code keeps the modal open (the code is still valid) until
      // the attempts run out.
      if (ev.ok || !(ev.attempts_remaining > 0)) {
        return withCodes(state, withoutPeer(state.codes, ev.peer));
      }
      return withCodes(
        state,
        state.codes.map((c) => (c === code ? { ...c, attemptsRemaining: ev.attempts_remaining } : c)),
      );
    }
    case "paired_peers_changed":
      return { ...state, pairedPeers: ev.peers };
    case "peer_error":
      return addNotice(
        state,
        "peer",
        `${peerLabel(state, ev.peer)} reported an error (${isolate(clip(ev.code, MAX_LABEL_CHARS))}): ${isolate(
          clip(ev.message, MAX_NOTICE_TEXT),
        )}`,
      );
    case "version_mismatch":
      return addNotice(
        state,
        "version",
        `Update Ventriloquist on ${isolate(clip(ev.device, MAX_LABEL_CHARS))}`,
      );
    case "message_rejected":
      return state; // diagnostics only
    case "log_warning":
      return { ...state, logWarning: ev.message };
    case "log_recovered":
      return state.logWarning === null ? state : { ...state, logWarning: null };
    case "storage_warning":
      return addNotice(state, "storage", clip(ev.message, MAX_NOTICE_TEXT));
    case "adapter_state":
      return state.adapter === ev.state ? state : { ...state, adapter: ev.state };
    case "config_changed":
      return { ...state, logDir: ev.log_dir, name: ev.name, configPersisted: ev.persisted };
  }
}

function withoutPeer(codes: readonly PairingModal[], peer: string): PairingModal[] {
  return codes.filter((c) => c.peer !== peer);
}

/** Set the pending codes (oldest dropped past the cap); the newest is shown. */
function withCodes(state: AppState, codes: readonly PairingModal[]): AppState {
  const kept = codes.length > MAX_CODES ? codes.slice(-MAX_CODES) : codes;
  return { ...state, codes: kept, pairing: kept.length > 0 ? kept[kept.length - 1]! : null };
}

function applySnapshot(
  state: AppState,
  snap: Extract<HostEvent, { event: "snapshot" }>,
  now: number,
): AppState {
  if (state.phase === "ready") {
    // A snapshot after ready is a late reply to an earlier request (ask()
    // retries): it may be older than live events. Merge, highest rev wins;
    // never regress or drop an entry (U4, U5).
    let next = state;
    for (const e of snap.entries) next = upsertEntry(next, e);
    return next;
  }
  void now;
  const peers = new Map<string, PeerInfo>();
  const codes: PairingModal[] = [];
  const t = mono();
  for (const p of snap.peers) {
    if (p.state === "closed") continue;
    peers.set(p.peer, {
      peer: p.peer,
      state: p.state,
      device_id: p.device_id,
      name: p.name,
      paired: p.paired,
    });
    if (p.pairing !== null) {
      const ms = codeLifetimeMs(p.pairing.expires_in_secs);
      if (ms > 0) {
        codes.push({
          peer: p.peer,
          phoneName: stripBidi(p.pairing.phone_name),
          code: p.pairing.code,
          deadline: t + ms,
          attemptsRemaining: null,
        });
      }
    }
  }
  const entries = new Map<string, Entry>();
  const order: string[] = [];
  for (const e of snap.entries) {
    const prev = entries.get(e.id);
    if (prev === undefined) {
      order.push(e.id);
      entries.set(e.id, e);
    } else if (accepts(prev, e)) {
      entries.set(e.id, e); // a duplicated id: the highest rev wins (U6)
    }
  }
  const keepCleared = new Map<string, number>();
  for (const [id, rev] of state.cleared) if (entries.has(id)) keepCleared.set(id, rev);

  let next: AppState = {
    ...state,
    phase: state.phase === "fatal" ? "fatal" : "ready",
    buffered: [],
    deviceId: snap.device_id,
    name: snap.name,
    logDir: snap.log_dir,
    pairedPeers: snap.paired_peers,
    adapter: snap.adapter_state,
    peers,
    entries,
    order: order.length > MAX_ENTRIES ? order.slice(-MAX_ENTRIES) : order,
    cleared: keepCleared,
    logWarning: snap.log_warning ?? null,
  };
  if (order.length > MAX_ENTRIES) {
    const kept = new Set(next.order);
    const trimmed = new Map([...entries].filter(([id]) => kept.has(id)));
    next = { ...next, entries: trimmed };
  }
  next = withCodes(next, codes);

  // Merge what arrived before the snapshot.
  const lastCode = new Map<string, { code: string; phoneName: string; deadline: number }>();
  for (const { event: ev, at } of state.buffered) {
    switch (ev.event) {
      case "entry_upserted":
      case "entry_evicted":
      case "log_warning":
      case "log_recovered":
      case "storage_warning":
      case "peer_error":
      case "version_mismatch":
        next = applyEvent(next, ev, at);
        break;
      case "pairing_code_shown":
        lastCode.set(ev.peer, {
          code: ev.code,
          phoneName: stripBidi(ev.phone_name),
          deadline: at + codeLifetimeMs(ev.expires_in_secs),
        });
        break;
      case "pairing_code_ended":
        lastCode.delete(ev.peer);
        break;
      default:
        break; // state events: the snapshot supersedes them
    }
  }
  // A code delivered ahead of the snapshot (coalescing) is newer than the
  // snapshot's code for the same connection.
  next = withCodes(
    next,
    next.codes
      .map((c) => {
        const newer = lastCode.get(c.peer);
        return newer !== undefined && newer.code !== c.code ? { ...c, ...newer } : c;
      })
      .filter((c) => c.deadline > t),
  );
  return next;
}

function clearView(state: AppState): AppState {
  const cleared = new Map(state.cleared);
  for (const id of state.order) {
    const e = state.entries.get(id);
    if (e !== undefined) cleared.set(id, e.rev);
  }
  return { ...state, cleared };
}

// ------------------------------------------------------------- selectors

/** Whether an entry is hidden by Clear view. */
export function isCleared(state: AppState, e: Entry): boolean {
  const rev = state.cleared.get(e.id);
  return rev !== undefined && e.rev <= rev;
}

const foldCache = new WeakMap<Entry, string>();
// eslint-disable-next-line no-control-regex
const ASCII_ONLY = /^[\u0000-\u007f]*$/;

/** Case- and accent-insensitive key for searching: NFKD, combining marks
 * removed, then lower-cased, so "İSTANBUL" ("i̇" after lower-casing alone)
 * matches "istanbul". Locale-independent. */
export function fold(s: string): string {
  return ASCII_ONLY.test(s) ? s.toLowerCase() : s.normalize("NFKD").replace(/\p{M}/gu, "").toLowerCase();
}

/** Case-insensitive substring match of the entry text (see {@link fold}).
 * The folded text is cached per entry object. */
export function matchesSearch(e: Entry, query: string): boolean {
  if (query === "") return true;
  let f = foldCache.get(e);
  if (f === undefined) {
    f = fold(e.text);
    foldCache.set(e, f);
  }
  return f.includes(fold(query));
}

/** Entries on screen, oldest first: not cleared, matching the search. */
export function visibleEntries(state: AppState): Entry[] {
  const out: Entry[] = [];
  for (const id of state.order) {
    const e = state.entries.get(id);
    if (e !== undefined && !isCleared(state, e) && matchesSearch(e, state.search)) out.push(e);
  }
  return out;
}

/** Entries not hidden by Clear view (search ignored). */
export function entriesInView(state: AppState): number {
  let n = 0;
  for (const id of state.order) {
    const e = state.entries.get(id);
    if (e !== undefined && !isCleared(state, e)) n++;
  }
  return n;
}

/** Exactly the text to put on the clipboard: the entry text, unchanged
 * (no trailing newline added, nothing trimmed). */
export function copyText(e: Entry): string {
  return e.text;
}

/** Ids of the paired phones that are currently connected and secure. */
export function onlineDeviceIds(state: AppState): Set<string> {
  const s = new Set<string>();
  for (const p of state.peers.values()) {
    if (p.state === "secure" && p.device_id !== null) s.add(p.device_id);
  }
  return s;
}
