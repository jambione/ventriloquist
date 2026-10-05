// Pure presentation helpers (unit-tested).

import { clip, isolate, stripBidi } from "./bidi";
import type { AppState, PeerInfo } from "./state";
import type {
  DeliveryEvent,
  HotkeyView,
  Modifier,
  RelayReason,
  RelayStatus,
  SlotsView,
  SlotView,
  TestReport,
} from "./types";

export type Platform = "mac" | "windows" | "other";

export function detectPlatform(userAgent: string): Platform {
  if (/Mac/i.test(userAgent)) return "mac";
  if (/Windows/i.test(userAgent)) return "windows";
  return "other";
}

/** "Ventriloquist v0.2.2 (abc1234)"; the commit is omitted when unknown. */
export function formatVersion(version: string, commit: string): string {
  const c = commit && commit !== "unknown" ? ` (${commit})` : "";
  return `Ventriloquist v${version}${c}`;
}

/** "123456" → "123 456". Anything that is not 6 digits is returned as is. */
export function formatCode(code: string): string {
  return /^[0-9]{6}$/.test(code) ? `${code.slice(0, 3)} ${code.slice(3)}` : code;
}

/** Longest countdown shown (a code never lives longer; state.ts caps it). */
const MAX_COUNTDOWN_MS = 3_600_000;

/** Remaining time as "m:ss", rounded up to the whole second, clamped to
 * 0:00 … 60:00; NaN shows 0:00. */
export function formatCountdown(remainingMs: number): string {
  const ms = Number.isNaN(remainingMs) ? 0 : Math.min(Math.max(remainingMs, 0), MAX_COUNTDOWN_MS);
  const secs = Math.ceil(ms / 1000);
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return `${m}:${s.toString().padStart(2, "0")}`;
}

/** Whether a scroll container is (within `slack` px) at the bottom. Measure
 * before the DOM changes; auto-scroll afterwards only if this was true. */
export function isAtBottom(
  scrollTop: number,
  scrollHeight: number,
  clientHeight: number,
  slack = 8,
): boolean {
  return scrollHeight - (scrollTop + clientHeight) <= slack;
}

export type StatusTone = "ok" | "busy" | "idle" | "warn";

export interface StatusView {
  tone: StatusTone;
  /** Shown after a coloured "●". */
  text: string;
  /** Technical detail for a tooltip (never contains a secret). */
  detail?: string | undefined;
}

/** Names shown in the status line: at most this many, each clipped. */
const MAX_STATUS_NAMES = 2;
const MAX_STATUS_NAME_CHARS = 32;

function names(peers: PeerInfo[]): string {
  const uniq = [
    ...new Set(peers.map((p) => clip(stripBidi(p.name ?? "phone"), MAX_STATUS_NAME_CHARS))),
  ];
  const shown = uniq.slice(0, MAX_STATUS_NAMES).map(isolate).join(", ");
  return uniq.length > MAX_STATUS_NAMES ? `${shown} and ${uniq.length - MAX_STATUS_NAMES} more` : shown;
}

/** Short, human reason for an unreachable relay (SPEC_V3 §6). */
export function relayReasonText(reason: RelayReason | null): string {
  switch (reason) {
    case "dns":
      return "DNS lookup failed";
    case "proxy_auth_required":
      return "proxy needs credentials";
    case "proxy_auth_unsupported":
      return "proxy requires Windows sign-in (NTLM/Kerberos) — not supported yet";
    case "proxy_blocked":
      return "proxy blocked";
    case "tls_untrusted":
      return "certificate not trusted";
    case "owner_token_rejected":
      return "owner token rejected";
    case "room_conflict":
      return "room conflict";
    case "other":
    case null:
      return "connection failed";
  }
}

/** What to do about an unreachable relay (Settings → Relay). */
export function relayReasonHint(reason: RelayReason | null): string {
  switch (reason) {
    case "dns":
      return "The relay's address could not be resolved. Check the relay URL and the network.";
    case "proxy_auth_required":
      return "The proxy asks for credentials, which are not supported (NTLM/Kerberos). Ask IT to allow the relay host without sign-in.";
    case "proxy_auth_unsupported":
      return "The proxy only accepts Windows sign-in (NTLM/Kerberos), which Ventriloquist does not support yet. Ask IT to allow the relay host without sign-in, or use a proxy URL with Basic credentials in HTTPS_PROXY.";
    case "proxy_blocked":
      return "The proxy refused the connection to the relay. Ask IT to allow the relay host on port 443.";
    case "tls_untrusted":
      return "The relay's certificate is not trusted by this computer (a TLS-inspecting proxy whose root certificate is not installed in the OS store?).";
    case "owner_token_rejected":
      return "The relay rejected the owner token, or the room does not exist yet and no owner token is set. Paste the relay's owner token above.";
    case "room_conflict":
      return "The room already exists on the relay with another secret (or was deleted). Use “Reset relay room”.";
    case "other":
    case null:
      return "The relay could not be reached.";
  }
}

/** One line for the relay link (Settings → Relay). */
export function relayStatusLine(r: RelayStatus): string {
  switch (r.link) {
    case "websocket":
      return "Connected via relay (WebSocket)";
    case "fallback":
      return "Connected via relay (fallback: HTTPS long-poll)";
    case "connecting":
      return "Connecting to the relay…";
    case "unreachable":
      return `Relay unreachable — ${relayReasonText(r.reason)}`;
    case "idle":
      return "Not connected";
  }
}

/** The outcome of "Test connection" as a sentence. */
export function testReportText(t: TestReport): string {
  const r = t.status;
  switch (r.link) {
    case "websocket":
      return "OK: the relay is reachable and WebSockets work.";
    case "fallback":
      return "The relay is reachable, but WebSockets are blocked: the HTTPS fallback will be used.";
    case "unreachable":
      return `Failed — ${relayReasonText(r.reason)}. ${relayReasonHint(r.reason)}`;
    default:
      return relayStatusLine(r);
  }
}

/** Toolbar connection status (SPEC_V3 §6). */
export function connectionStatus(state: AppState): StatusView {
  if (state.phase === "fatal") return { tone: "warn", text: "Not running" };
  if (state.phase === "loading") return { tone: "idle", text: "Starting…" };
  const relay = state.relay;
  const detail = relay.detail ?? undefined;
  if (relay.link === "unreachable") {
    return { tone: "warn", text: `Relay unreachable — ${relayReasonText(relay.reason)}`, detail };
  }
  const via =
    relay.link === "websocket" ? " via relay (WebSocket)" : relay.link === "fallback" ? " via relay (fallback)" : "";
  const peers = [...state.peers.values()];
  const secure = peers.filter((p) => p.state === "secure");
  if (secure.length > 0) {
    return { tone: "ok", text: `Connected to ${names(secure)} (secure)${relay.link === "fallback" ? " · relay fallback" : ""}` };
  }
  const pairing = peers.filter((p) => p.state === "pairing");
  if (pairing.length > 0) return { tone: "busy", text: `Pairing with ${names(pairing)}…` };
  const connecting = peers.filter(
    (p) => p.state === "connected" || (p.state === "hello_exchanged" && p.paired),
  );
  if (connecting.length > 0) return { tone: "busy", text: `Connecting to ${names(connecting)}…` };
  const unpaired = peers.filter((p) => p.state === "hello_exchanged" && !p.paired);
  if (unpaired.length > 0) {
    return { tone: "busy", text: `${names(unpaired)} found — pair from the phone` };
  }
  if (relay.link === "connecting") return { tone: "busy", text: "Connecting to the relay…" };
  if (via !== "") return { tone: "idle", text: `Connected${via} · Waiting for iPhone` };
  return { tone: "idle", text: "Waiting for iPhone" };
}

/** Whether to show the "Add phone" QR on its own: once per run, as soon as
 * the state is known, while no phone is paired. */
export function shouldAutoShowQr(state: AppState, alreadyShown: boolean): boolean {
  return !alreadyShown && state.phase === "ready" && state.pairedPeers.length === 0 && state.phonePairing === null;
}

/** Local date of a pairing, e.g. "2026-10-03"; "" for anything that is not
 * a plausible date (non-finite, or outside the years 1900…9999). */
export function formatDate(ms: number): string {
  if (!Number.isFinite(ms)) return "";
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return "";
  if (d.getFullYear() < 1900 || d.getFullYear() > 9999) return "";
  const p = (n: number): string => n.toString().padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

// ---------------------------------------------------------------- bindings

const MAX_CHIP_CHARS = 28;
const MAX_REASON_CHARS = 80;

export interface ChipView {
  /** 0 = Off. */
  slot: number;
  /** Plain text for textContent; app and title are bidi-isolated. */
  label: string;
  tooltip: string;
  bound: boolean;
  active: boolean;
  /** Re-matched, no delivery yet: shows "?". */
  unverified: boolean;
  /** Saved but not found: dimmed, "rebind". */
  unbound: boolean;
  /** Shows the "⏎" marker. */
  autoSubmit: boolean;
}

function chipText(s: SlotView, max: number): string {
  const app = isolate(clip(s.app_name, max));
  return s.window_title === ""
    ? `${s.slot} · ${app}`
    : `${s.slot} · ${app} — ${isolate(clip(s.window_title, max))}`;
}

/** The slot bar: Off, then 1…9 (unbound chips dimmed). */
export function slotChips(view: SlotsView | null): ChipView[] {
  const active = view?.active ?? 0;
  const chips: ChipView[] = [
    {
      slot: 0,
      label: "Off",
      tooltip: "Off: nothing is sent to other apps",
      bound: true,
      active: active === 0,
      unverified: false,
      unbound: false,
      autoSubmit: false,
    },
  ];
  for (let n = 1; n <= 9; n++) {
    const s = view?.slots.find((x) => x.slot === n);
    if (s === undefined) {
      chips.push({
        slot: n,
        label: String(n),
        tooltip: `Slot ${n} is empty`,
        bound: false,
        active: false,
        unverified: false,
        unbound: false,
        autoSubmit: false,
      });
    } else {
      chips.push({
        slot: n,
        label: chipText(s, MAX_CHIP_CHARS),
        tooltip:
          chipText(s, 200) +
          (s.status === "unbound" ? " (not found: rebind it)" : "") +
          (s.status === "unverified" ? " (not verified yet)" : "") +
          (s.auto_submit ? " (presses Enter after the text)" : ""),
        bound: true,
        active: active === n,
        unverified: s.status === "unverified",
        unbound: s.status === "unbound",
        autoSubmit: s.auto_submit,
      });
    }
  }
  return chips;
}

export type BadgeTone = "ok" | "off" | "warn" | "busy";

export interface DeliveryBadge {
  tone: BadgeTone;
  text: string;
}

/** The per-entry delivery badge (SPEC_V2 §4.5); null when nothing was tried. */
export function deliveryBadge(d: DeliveryEvent | undefined): DeliveryBadge | null {
  if (d === undefined) return null;
  const slot = d.slot === null ? "" : String(d.slot);
  const app = d.app_name === null ? "" : isolate(clip(d.app_name, 24));
  const reason = d.reason === null ? "" : isolate(clip(d.reason, MAX_REASON_CHARS));
  switch (d.status) {
    case "sending":
      return { tone: "busy", text: "sending…" };
    case "sent":
      return { tone: "ok", text: `→ ${slot} · ${app} ✓` };
    case "off":
      return { tone: "off", text: "not sent (Off)" };
    case "missing":
      return { tone: "warn", text: `✗ slot ${slot} missing` };
    case "blocked":
      return { tone: "warn", text: `⚠ blocked (${reason})` };
    case "failed":
      return { tone: "warn", text: `✗ failed: ${reason}` };
  }
}

/** Whether "Send to active slot" is enabled: a slot is active and the entry
 * is not a live or interrupted partial. */
export function canSendToActive(view: SlotsView | null, state: string): boolean {
  return (view?.active ?? 0) !== 0 && (state === "final" || state === "edit");
}

/** Modifier checkboxes in display order, labelled for the platform. */
export function modifierChoices(platform: Platform): { mod: Modifier; label: string }[] {
  const mac = platform === "mac";
  return [
    { mod: "ctrl", label: "Ctrl" },
    { mod: "alt", label: mac ? "Option" : "Alt" },
    { mod: "shift", label: "Shift" },
    { mod: "super", label: mac ? "Cmd" : "Win" },
  ];
}

/** "Ctrl+Shift+0–9" for a modifier set and digit range. */
export function formatHotkey(mods: readonly Modifier[], range: string, platform: Platform): string {
  const labels = modifierChoices(platform)
    .filter((c) => mods.includes(c.mod))
    .map((c) => c.label);
  return [...labels, range].join("+");
}

/** "taken by another app: 0, 3" or "" when everything registered. */
export function takenText(digits: readonly number[]): string {
  return digits.length === 0 ? "" : `taken by another app: ${digits.join(", ")}`;
}

/** Whether the hotkey part of two views is the same (render skipping). */
export function sameHotkeys(a: HotkeyView | undefined, b: HotkeyView | undefined): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}
