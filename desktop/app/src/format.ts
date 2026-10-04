// Pure presentation helpers (unit-tested).

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

/** Remaining time as "m:ss", rounded up to the whole second, never negative. */
export function formatCountdown(remainingMs: number): string {
  const secs = Math.max(0, Math.ceil(remainingMs / 1000));
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

function names(peers: PeerInfo[]): string {
  const uniq = [...new Set(peers.map((p) => p.name ?? "phone"))];
  return uniq.join(", ");
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

/** Local date of a pairing, e.g. "2026-10-03". */
export function formatDate(ms: number): string {
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return "";
  const p = (n: number): string => n.toString().padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}
