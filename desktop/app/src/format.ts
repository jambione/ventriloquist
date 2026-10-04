// Pure presentation helpers (unit-tested).

import { clip, isolate, stripBidi } from "./bidi";
import type { AppState, PeerInfo } from "./state";

export type Platform = "mac" | "windows" | "other";

export function detectPlatform(userAgent: string): Platform {
  if (/Mac/i.test(userAgent)) return "mac";
  if (/Windows/i.test(userAgent)) return "windows";
  return "other";
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

/** Toolbar connection status (SPEC §6.1, §6.3). */
export function connectionStatus(state: AppState, platform: Platform): StatusView {
  if (state.phase === "fatal") return { tone: "warn", text: "Not running" };
  if (state.phase === "loading") return { tone: "idle", text: "Starting…" };
  switch (state.adapter) {
    case "powered_off":
      return { tone: "warn", text: "Bluetooth off" };
    case "unauthorized":
      return {
        tone: "warn",
        text:
          platform === "windows"
            ? "Bluetooth not allowed — enable it in Settings › Privacy & security"
            : "Bluetooth not authorized — enable in System Settings",
      };
    case "no_adapter":
      return { tone: "warn", text: "No Bluetooth adapter" };
    default:
      break;
  }
  const peers = [...state.peers.values()];
  const secure = peers.filter((p) => p.state === "secure");
  if (secure.length > 0) return { tone: "ok", text: `Connected to ${names(secure)} (secure)` };
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
  if (state.adapter === "scanning") return { tone: "idle", text: "Scanning…" };
  return { tone: "idle", text: "Starting Bluetooth…" };
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
