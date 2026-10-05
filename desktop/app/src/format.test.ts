import { describe, expect, it } from "vitest";
import {
  connectionStatus,
  detectPlatform,
  formatCode,
  formatCountdown,
  formatVersion,
  isAtBottom,
  relayReasonHint,
  relayReasonText,
  relayStatusLine,
  shouldAutoShowQr,
  testReportText,
} from "./format";
import { initialState, reduce, type AppState } from "./state";
import type { HostEvent, PeerState, RelayLink, RelayReason, RelayStatus } from "./types";

describe("formatCode", () => {
  it("groups six digits", () => {
    expect(formatCode("123456")).toBe("123 456");
    expect(formatCode("042917")).toBe("042 917");
    expect(formatCode("12345")).toBe("12345");
  });
});

describe("formatCountdown", () => {
  it("formats m:ss, rounding up, never negative", () => {
    expect(formatCountdown(120_000)).toBe("2:00");
    expect(formatCountdown(119_001)).toBe("2:00");
    expect(formatCountdown(119_000)).toBe("1:59");
    expect(formatCountdown(61_000)).toBe("1:01");
    expect(formatCountdown(9_500)).toBe("0:10");
    expect(formatCountdown(1)).toBe("0:01");
    expect(formatCountdown(0)).toBe("0:00");
    expect(formatCountdown(-5000)).toBe("0:00");
  });
});

describe("isAtBottom (auto-scroll decision)", () => {
  it("is true at or near the bottom", () => {
    expect(isAtBottom(600, 1000, 400)).toBe(true);
    expect(isAtBottom(595, 1000, 400)).toBe(true);
    expect(isAtBottom(0, 300, 400)).toBe(true); // content shorter than the view
  });
  it("is false when the user scrolled up", () => {
    expect(isAtBottom(500, 1000, 400)).toBe(false);
    expect(isAtBottom(0, 1000, 400)).toBe(false);
  });
});

const relay = (link: RelayLink, reason: RelayReason | null = null, detail: string | null = null): RelayStatus => ({
  link,
  reason,
  detail,
});

describe("connectionStatus", () => {
  const snap = (
    r: RelayStatus,
    peers: { state: PeerState; name: string; paired: boolean }[],
    paired: { device_id: string; name: string; public_key: string; paired_at_ms: number }[] = [],
  ): AppState =>
    reduce(initialState(), {
      type: "host",
      now: 0,
      event: {
        event: "snapshot",
        device_id: "d",
        name: "Mac",
        log_dir: "/l",
        paired_peers: paired,
        relay: r,
        entries: [],
        peers: peers.map((p, i) => ({
          peer: `p${i}`,
          state: p.state,
          device_id: `dev${i}`,
          name: p.name,
          paired: p.paired,
          pairing: null,
        })),
      } satisfies HostEvent,
    });

  it("reports the relay link (SPEC_V3 §6)", () => {
    expect(connectionStatus(initialState()).text).toBe("Starting…");
    expect(connectionStatus(snap(relay("connecting"), []))).toEqual({ tone: "busy", text: "Connecting to the relay…" });
    expect(connectionStatus(snap(relay("websocket"), []))).toEqual({
      tone: "idle",
      text: "Connected via relay (WebSocket) · Waiting for iPhone",
    });
    expect(connectionStatus(snap(relay("fallback"), []))).toEqual({
      tone: "idle",
      text: "Connected via relay (fallback) · Waiting for iPhone",
    });
    // No relay information (the TCP dev transport): the phone hint only.
    expect(connectionStatus(snap(relay("idle"), []))).toEqual({ tone: "idle", text: "Waiting for iPhone" });
  });

  it("names the reason when the relay is unreachable", () => {
    const cases: [RelayReason, string][] = [
      ["dns", "Relay unreachable — DNS lookup failed"],
      ["proxy_auth_required", "Relay unreachable — proxy needs credentials"],
      ["proxy_blocked", "Relay unreachable — proxy blocked"],
      ["tls_untrusted", "Relay unreachable — certificate not trusted"],
      ["owner_token_rejected", "Relay unreachable — owner token rejected"],
      ["room_conflict", "Relay unreachable — room conflict"],
      ["other", "Relay unreachable — connection failed"],
    ];
    for (const [reason, text] of cases) {
      expect(connectionStatus(snap(relay("unreachable", reason, "tech detail"), []))).toEqual({
        tone: "warn",
        text,
        detail: "tech detail",
      });
    }
  });

  it("reports phone connections", () => {
    const ws = relay("websocket");
    expect(connectionStatus(snap(ws, [{ state: "secure", name: "Jon's iPhone", paired: true }]))).toEqual({
      tone: "ok",
      text: "Connected to \u2068Jon's iPhone\u2069 (secure)",
    });
    expect(connectionStatus(snap(relay("fallback"), [{ state: "secure", name: "P", paired: true }])).text).toBe(
      "Connected to \u2068P\u2069 (secure) · relay fallback",
    );
    expect(connectionStatus(snap(ws, [{ state: "pairing", name: "A", paired: false }])).text).toBe(
      "Pairing with \u2068A\u2069…",
    );
    expect(connectionStatus(snap(ws, [{ state: "connected", name: "A", paired: false }])).text).toBe(
      "Connecting to \u2068A\u2069…",
    );
    expect(connectionStatus(snap(ws, [{ state: "hello_exchanged", name: "A", paired: false }])).text).toBe(
      "\u2068A\u2069 found — pair from the phone",
    );
    expect(connectionStatus(reduce(initialState(), { type: "fatal", message: "x" })).tone).toBe("warn");
  });

  it("an unreachable relay wins over stale peers", () => {
    expect(
      connectionStatus(snap(relay("unreachable", "dns"), [{ state: "secure", name: "P", paired: true }])).tone,
    ).toBe("warn");
  });

  it("never mentions Bluetooth any more", () => {
    for (const l of ["idle", "connecting", "websocket", "fallback", "unreachable"] as RelayLink[]) {
      expect(connectionStatus(snap(relay(l, l === "unreachable" ? "other" : null), [])).text).not.toMatch(/bluetooth/i);
    }
  });

  it("detects the platform", () => {
    expect(detectPlatform("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")).toBe("mac");
    expect(detectPlatform("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")).toBe("windows");
  });
});

describe("relay texts", () => {
  it("status lines", () => {
    expect(relayStatusLine(relay("websocket"))).toBe("Connected via relay (WebSocket)");
    expect(relayStatusLine(relay("fallback"))).toBe("Connected via relay (fallback: HTTPS long-poll)");
    expect(relayStatusLine(relay("unreachable", "tls_untrusted"))).toBe("Relay unreachable — certificate not trusted");
    expect(relayStatusLine(relay("idle"))).toBe("Not connected");
  });

  it("every reason has a text and a hint", () => {
    for (const r of [null, "dns", "proxy_auth_required", "proxy_blocked", "tls_untrusted", "owner_token_rejected", "room_conflict", "other"] as (RelayReason | null)[]) {
      expect(relayReasonText(r).length).toBeGreaterThan(3);
      expect(relayReasonHint(r).length).toBeGreaterThan(10);
    }
  });

  it("Test connection results", () => {
    expect(testReportText({ status: relay("websocket"), checked: [] })).toMatch(/^OK/);
    expect(testReportText({ status: relay("fallback"), checked: [] })).toMatch(/WebSockets are blocked/);
    const failed = testReportText({ status: relay("unreachable", "proxy_blocked"), checked: [] });
    expect(failed).toMatch(/^Failed — proxy blocked\./);
  });
});

describe("shouldAutoShowQr", () => {
  const peer = { device_id: "x", name: "P", public_key: "k", paired_at_ms: 1 };
  it("shows once, in the ready state, while no phone is paired", () => {
    const ready = snap0([]);
    expect(shouldAutoShowQr(initialState(), false)).toBe(false); // still loading
    expect(shouldAutoShowQr(ready, false)).toBe(true);
    expect(shouldAutoShowQr(ready, true)).toBe(false);
    expect(shouldAutoShowQr(snap0([peer]), false)).toBe(false);
  });
  it("does not show on top of an open dialog", () => {
    const open = reduce(snap0([]), {
      type: "host",
      now: 0,
      event: { event: "phone_pairing_qr", uri: "vq://pair?x", expires_in_secs: 120 },
    });
    expect(shouldAutoShowQr(open, false)).toBe(false);
  });
  function snap0(paired: (typeof peer)[]): AppState {
    return reduce(initialState(), {
      type: "host",
      now: 0,
      event: {
        event: "snapshot",
        device_id: "d",
        name: "Mac",
        log_dir: "/l",
        paired_peers: paired,
        relay: relay("websocket"),
        entries: [],
        peers: [],
      },
    });
  }
});

describe("formatVersion", () => {
  it("shows version and commit", () => {
    expect(formatVersion("0.2.2", "abc1234")).toBe("Ventriloquist v0.2.2 (abc1234)");
  });
  it("omits an unknown or empty commit", () => {
    expect(formatVersion("0.2.2", "unknown")).toBe("Ventriloquist v0.2.2");
    expect(formatVersion("0.2.2", "")).toBe("Ventriloquist v0.2.2");
  });
});
