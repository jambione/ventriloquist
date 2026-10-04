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

import type {
  AdapterState,
  Entry,
  HostEvent,
  PairedPeer,
  PeerState,
} from "./types";

/** In-memory history cap (SPEC §6.1); the core enforces it too. */
export const MAX_ENTRIES = 500;
/** Pre-snapshot events kept; older ones are dropped (the snapshot covers them). */
export const MAX_BUFFERED = 2000;
/** Dismissible notices kept on screen. */
export const MAX_NOTICES = 5;
/** Longest peer-provided message shown in a notice (characters). */
export const MAX_NOTICE_TEXT = 200;

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

export type NoticeKind = "storage" | "peer" | "version";

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
  search: string;
  pairing: PairingModal | null;
  logWarning: string | null;
  notices: readonly Notice[];
  nextNoticeId: number;
}

export type Action =
  | { type: "host"; event: HostEvent; now: number }
  | { type: "search"; query: string }
  | { type: "clear_view" }
  | { type: "tick"; now: number }
  | { type: "dismiss_pairing" }
  | { type: "dismiss_notice"; id: number }
  | { type: "fatal"; message: string };

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
    search: "",
    pairing: null,
    logWarning: null,
    notices: [],
    nextNoticeId: 1,
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
      return state.pairing !== null && action.now >= state.pairing.deadline
        ? { ...state, pairing: null }
        : state;
    case "dismiss_pairing":
      return state.pairing === null ? state : { ...state, pairing: null };
    case "dismiss_notice":
      return { ...state, notices: state.notices.filter((n) => n.id !== action.id) };
    case "fatal":
      return { ...state, phase: "fatal", fatal: action.message, buffered: [] };
  }
}

// ---------------------------------------------------------------- events

function onHostEvent(state: AppState, ev: HostEvent, now: number): AppState {
  if (ev.event === "snapshot") {
    return applySnapshot(state, ev, now);
  }
  if (state.phase === "loading") {
    const buffered = [...state.buffered, { event: ev, at: now }];
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
        entries.delete(id);
        c.delete(id);
      }
      cleared = c;
    }
    order = next;
  }
  return { ...state, entries, order, cleared };
}

function evictEntry(state: AppState, id: string): AppState {
  if (!state.entries.has(id)) return state;
  const entries = new Map(state.entries);
  entries.delete(id);
  const cleared = new Map(state.cleared);
  cleared.delete(id);
  return { ...state, entries, cleared, order: state.order.filter((x) => x !== id) };
}

function addNotice(state: AppState, kind: NoticeKind, text: string): AppState {
  const notice: Notice = { id: state.nextNoticeId, kind, text: truncate(text, MAX_NOTICE_TEXT) };
  const notices = [...state.notices, notice].slice(-MAX_NOTICES);
  return { ...state, notices, nextNoticeId: state.nextNoticeId + 1 };
}

function truncate(s: string, max: number): string {
  const chars = Array.from(s);
  return chars.length <= max ? s : chars.slice(0, max).join("") + "…";
}

function peerLabel(state: AppState, peer: string, fallback: string | null = null): string {
  return state.peers.get(peer)?.name ?? fallback ?? "a phone";
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
      const pairing =
        ev.state === "closed" && state.pairing?.peer === ev.peer ? null : state.pairing;
      return { ...state, peers, pairing };
    }
    case "pairing_code_shown":
      // One modal at a time; a new code replaces any previous one.
      return {
        ...state,
        pairing: {
          peer: ev.peer,
          phoneName: ev.phone_name,
          code: ev.code,
          deadline: now + ev.expires_in_secs * 1000,
          attemptsRemaining: null,
        },
      };
    case "pairing_code_ended":
      return state.pairing?.peer === ev.peer ? { ...state, pairing: null } : state;
    case "pairing_result": {
      if (state.pairing?.peer !== ev.peer) return state;
      // A wrong code keeps the modal open (the code is still valid) until
      // the attempts run out.
      if (ev.ok || ev.attempts_remaining === 0) return { ...state, pairing: null };
      return { ...state, pairing: { ...state.pairing, attemptsRemaining: ev.attempts_remaining } };
    }
    case "paired_peers_changed":
      return { ...state, pairedPeers: ev.peers };
    case "peer_error":
      return addNotice(
        state,
        "peer",
        `${peerLabel(state, ev.peer)} reported an error (${ev.code}): ${ev.message}`,
      );
    case "version_mismatch":
      return addNotice(state, "version", `Update Ventriloquist on ${ev.device}`);
    case "message_rejected":
      return state; // diagnostics only
    case "log_warning":
      return { ...state, logWarning: ev.message };
    case "log_recovered":
      return state.logWarning === null ? state : { ...state, logWarning: null };
    case "storage_warning":
      return addNotice(state, "storage", ev.message);
    case "adapter_state":
      return state.adapter === ev.state ? state : { ...state, adapter: ev.state };
    case "config_changed":
      return { ...state, logDir: ev.log_dir, name: ev.name, configPersisted: ev.persisted };
  }
}

function applySnapshot(
  state: AppState,
  snap: Extract<HostEvent, { event: "snapshot" }>,
  now: number,
): AppState {
  const peers = new Map<string, PeerInfo>();
  let pairing: PairingModal | null = null;
  for (const p of snap.peers) {
    if (p.state === "closed") continue;
    peers.set(p.peer, {
      peer: p.peer,
      state: p.state,
      device_id: p.device_id,
      name: p.name,
      paired: p.paired,
    });
    if (p.pairing !== null && pairing === null) {
      pairing = {
        peer: p.peer,
        phoneName: p.pairing.phone_name,
        code: p.pairing.code,
        deadline: now + p.pairing.expires_in_secs * 1000,
        attemptsRemaining: null,
      };
    }
  }
  const entries = new Map<string, Entry>();
  const order: string[] = [];
  for (const e of snap.entries) {
    if (!entries.has(e.id)) order.push(e.id);
    entries.set(e.id, e);
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
    pairing,
  };
  if (order.length > MAX_ENTRIES) {
    const kept = new Set(next.order);
    const trimmed = new Map([...entries].filter(([id]) => kept.has(id)));
    next = { ...next, entries: trimmed };
  }

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
          phoneName: ev.phone_name,
          deadline: at + ev.expires_in_secs * 1000,
        });
        break;
      case "pairing_code_ended":
        lastCode.delete(ev.peer);
        break;
      default:
        break; // state events: the snapshot supersedes them
    }
  }
  if (next.pairing !== null) {
    const newer = lastCode.get(next.pairing.peer);
    if (newer !== undefined && newer.code !== next.pairing.code) {
      next = { ...next, pairing: { ...next.pairing, ...newer } };
    }
  }
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

/** Case-insensitive substring match of the entry text. */
export function matchesSearch(e: Entry, query: string): boolean {
  if (query === "") return true;
  return e.text.toLowerCase().includes(query.toLowerCase());
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
