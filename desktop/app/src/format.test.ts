import { describe, expect, it } from "vitest";
import { connectionStatus, detectPlatform, formatCode, formatCountdown, isAtBottom } from "./format";
import { initialState, reduce, type AppState } from "./state";
import type { AdapterState, HostEvent, PeerState } from "./types";

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

describe("connectionStatus", () => {
  const snap = (adapter: AdapterState, peers: { state: PeerState; name: string; paired: boolean }[]): AppState =>
    reduce(initialState(), {
      type: "host",
      now: 0,
      event: {
        event: "snapshot",
        device_id: "d",
        name: "Mac",
        log_dir: "/l",
        paired_peers: [],
        adapter_state: adapter,
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

  it("reports the adapter and connections", () => {
    expect(connectionStatus(initialState(), "mac").text).toBe("Starting…");
    expect(connectionStatus(snap("scanning", []), "mac")).toEqual({ tone: "idle", text: "Scanning…" });
    expect(connectionStatus(snap("powered_off", []), "mac").text).toBe("Bluetooth off");
    expect(connectionStatus(snap("unauthorized", []), "mac").text).toBe(
      "Bluetooth not authorized — enable in System Settings",
    );
    expect(connectionStatus(snap("unauthorized", []), "windows").text).toContain("Settings");
    expect(connectionStatus(snap("scanning", [{ state: "secure", name: "Jon's iPhone", paired: true }]), "mac")).toEqual({
      tone: "ok",
      text: "Connected to Jon's iPhone (secure)",
    });
    expect(connectionStatus(snap("scanning", [{ state: "pairing", name: "A", paired: false }]), "mac").text).toBe(
      "Pairing with A…",
    );
    expect(connectionStatus(snap("scanning", [{ state: "connected", name: "A", paired: false }]), "mac").text).toBe(
      "Connecting to A…",
    );
    expect(
      connectionStatus(snap("scanning", [{ state: "hello_exchanged", name: "A", paired: false }]), "mac").text,
    ).toBe("A found — pair from the phone");
    expect(connectionStatus(reduce(initialState(), { type: "fatal", message: "x" }), "mac").tone).toBe("warn");
  });

  it("detects the platform", () => {
    expect(detectPlatform("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")).toBe("mac");
    expect(detectPlatform("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")).toBe("windows");
  });
});
