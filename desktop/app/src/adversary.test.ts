// M5 adversary suite: hostile event streams against the reducer, the
// formatters and the rendering code. Failing tests are findings.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { connectionStatus, formatCode, formatCountdown, formatDate } from "./format";
import {
  MAX_ENTRIES,
  MAX_NOTICES,
  MAX_NOTICE_TEXT,
  copyText,
  entriesInView,
  initialState,
  matchesSearch,
  reduce,
  visibleEntries,
  type AppState,
} from "./state";
import type { Entry, HostEvent, PeerStatus } from "./types";

const PHONE = "0f8fad5b-d9cb-469f-a165-70867728950e";
const T0 = 1_760_000_000_000;

function entry(id: string, rev: number, state: Entry["state"], text: string, name = "Phone"): Entry {
  return {
    id,
    rev,
    state,
    text,
    ts: T0,
    device_id: PHONE,
    device_name: name,
    first_received_at: "2026-10-03T14:03:21+02:00",
    received_at: "2026-10-03T14:03:22+02:00",
    time: "14:03:22",
    partial: state === "partial",
    edited: state === "edit",
  };
}

function snapshot(entries: Entry[] = [], peers: PeerStatus[] = []): HostEvent {
  return {
    event: "snapshot",
    device_id: "host",
    name: "Mac",
    log_dir: "/tmp/log",
    paired_peers: [],
    adapter_state: "scanning",
    peers,
    entries,
  };
}

const up = (e: Entry): HostEvent => ({ event: "entry_upserted", entry: e });

function feed(state: AppState, events: HostEvent[], now = T0): AppState {
  let s = state;
  for (const ev of events) s = reduce(s, { type: "host", event: ev, now });
  return s;
}

function ready(events: HostEvent[] = []): AppState {
  return feed(feed(initialState(), [snapshot()]), events);
}

function conn(peer: string, state: PeerStatus["state"], name: string | null, paired = false): HostEvent {
  return { event: "connection_status", peer, state, device_id: PHONE, name, paired, reason: null };
}

function codeShown(peer: string, code: string, secs: number, phone = "Phone"): HostEvent {
  return {
    event: "pairing_code_shown",
    peer,
    device_id: PHONE,
    phone_name: phone,
    code,
    expires_in_secs: secs,
  };
}

const RLO = "‮";
const BIDI_CONTROLS = /[‪-‮⁦-⁩‎‏؜]/;
void BIDI_CONTROLS; // kept for reference (noUnusedLocals)

/** Text after the peer-provided name must not be under the name's bidi
 * override: either the name is wrapped in an isolate (FSI…PDI), or the
 * override is stripped / terminated (PDF) before the trailing text. */
function overrideLeaks(composed: string, name: string): boolean {
  const i = composed.indexOf(name);
  if (i < 0) {
    // name was sanitized: leak only if an unterminated override remains
    return /‮[^‬⁩]*$/.test(composed);
  }
  const before = composed.slice(0, i);
  const after = composed.slice(i + name.length);
  const isolated = before.endsWith("⁨") && after.startsWith("⁩");
  return !isolated && after.length > 0;
}

// ============================================================ injection

describe("injection: rendering never parses peer strings as markup", () => {
  const main = readFileSync(new URL("./main.ts", import.meta.url), "utf8");

  it("main.ts uses no HTML-parsing sinks", () => {
    expect(main).not.toMatch(/\.innerHTML|\.outerHTML|insertAdjacentHTML|document\.write|DOMParser|createContextualFragment/);
  });

  it("main.ts setAttribute/className/href only receive constants or enum-derived values", () => {
    const sinks = [...main.matchAll(/setAttribute\(([^)]*)\)|\.(?:className|href|src|title|id)\s*=\s*([^;]+);/g)].map(
      (m) => m[0],
    );
    const peerish = /(text|device_name|phoneName|phone_name|\.name\b|message|logDir|code)\b/;
    for (const s of sinks) {
      const code = s.replace(/"[^"]*"/g, '""'); // string literals are constants
      expect(code, s).not.toMatch(peerish);
    }
  });

  it("no peer data reaches eval-like or URL sinks", () => {
    expect(main).not.toMatch(/\beval\(|new Function\(|location\.|window\.open\(|\.href\s*=/);
  });

  it("hostile entry text and names survive the reducer byte-for-byte", () => {
    const evil = [
      `<img src=x onerror=alert(1)>`,
      `</div><script>alert(1)</script>`,
      `javascript:alert(1)`,
      `${RLO}gnp.exe`,
      "a​‌‍﻿b",
      "nul\u0000bell\u0007esc\u001b[31m",
      "x".repeat(32_000),
    ];
    let s = ready();
    evil.forEach((t, i) => {
      s = feed(s, [up(entry(`e${i}`, 1, "final", t, `${RLO}${"א".repeat(63)}`))]);
    });
    const vis = visibleEntries(s);
    expect(vis.map((e) => e.text)).toEqual(evil);
    for (const e of vis) expect(copyText(e)).toBe(e.text);
  });
});

describe("injection: bidi spoofing in composed strings", () => {
  const name = `Bob${RLO}`;

  it("toolbar status isolates a phone name containing U+202E (\" (secure)\" must not be reordered)", () => {
    const s = ready([conn("p1", "secure", name, true)]);
    const text = connectionStatus(s, "mac").text;
    expect(overrideLeaks(text, name), JSON.stringify(text)).toBe(false);
  });

  it("peer_error notice isolates the peer name / message containing U+202E", () => {
    let s = ready([conn("p1", "hello_exchanged", name)]);
    s = feed(s, [
      { event: "peer_error", peer: "p1", code: "bad", message: `${RLO}evil`, authenticated: false },
    ]);
    const text = s.notices[0]!.text;
    expect(overrideLeaks(text, name), JSON.stringify(text)).toBe(false);
  });

  it("version_mismatch notice isolates the device name", () => {
    const s = ready([{ event: "version_mismatch", peer: "p1", device: `x${RLO}` }]);
    const text = s.notices[0]!.text;
    expect(overrideLeaks(text, `x${RLO}`), JSON.stringify(text)).toBe(false);
  });

  it("an unauthenticated peer_error message cannot carry bidi controls into a notice", () => {
    const s = ready([
      { event: "peer_error", peer: "p9", code: "x", message: `‭fake⁦`, authenticated: false },
    ]);
    // Either stripped or isolated; raw unbalanced controls are a spoofing vector.
    const t = s.notices[0]!.text;
    expect(/[\u202A-\u202E]/.test(t), JSON.stringify(t)).toBe(false);
  });

  it("notice truncation counts code points and never splits a surrogate pair", () => {
    const s = ready([{ event: "storage_warning", message: "😀".repeat(500) }]);
    const t = s.notices[0]!.text;
    expect(Array.from(t).length).toBe(MAX_NOTICE_TEXT + 1);
    expect(t).not.toMatch(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/);
  });
});

// ============================================================= ordering

describe("ordering", () => {
  it("events before snapshot are buffered and merged (newer partial kept)", () => {
    let s = feed(initialState(), [up(entry("a", 3, "partial", "newer"))]);
    s = feed(s, [snapshot([entry("a", 2, "partial", "older")])]);
    expect(s.entries.get("a")!.rev).toBe(3);
  });

  it("a snapshot arriving after ready does not regress an entry to a lower rev (W2 highest-rev rule)", () => {
    // ask() retries every 3 s while loading; the reply to an earlier
    // request can land after the UI went ready and after newer live events.
    let s = ready([up(entry("a", 4, "partial", "hello wor"))]);
    s = feed(s, [snapshot([entry("a", 3, "partial", "hello")])]);
    expect(s.entries.get("a")!.rev).toBe(4);
    expect(s.entries.get("a")!.text).toBe("hello wor");
  });

  it("a stale snapshot after ready does not drop entries that arrived live", () => {
    let s = ready([up(entry("live", 1, "final", "x"))]);
    s = feed(s, [snapshot([])]);
    expect(s.entries.has("live")).toBe(true);
  });

  it("snapshot with a duplicated id keeps the highest rev", () => {
    const s = feed(initialState(), [snapshot([entry("a", 5, "final", "new"), entry("a", 2, "partial", "old")])]);
    expect(s.entries.get("a")!.rev).toBe(5);
  });

  it("duplicate and lower-rev upserts are ignored", () => {
    let s = ready([up(entry("a", 2, "final", "final"))]);
    const before = s;
    s = feed(s, [up(entry("a", 2, "final", "final")), up(entry("a", 1, "partial", "p"))]);
    expect(s).toBe(before);
  });

  it("edit before final: late final with lower rev is ignored", () => {
    const s = ready([up(entry("a", 3, "edit", "edited")), up(entry("a", 2, "final", "orig"))]);
    expect(s.entries.get("a")!.text).toBe("edited");
  });

  it("interrupted after final at same rev is ignored", () => {
    const s = ready([up(entry("a", 2, "final", "done")), up(entry("a", 2, "interrupted", "done"))]);
    expect(s.entries.get("a")!.state).toBe("final");
  });

  it("evicted entry followed by a re-emitted interrupted (same rev) does not resurrect it", () => {
    // README: on close, live partials are re-emitted at the same rev with
    // state interrupted; the core keeps evicted ids, the UI forgets them.
    const s = ready([
      up(entry("a", 7, "partial", "p")),
      { event: "entry_evicted", id: "a" },
      up(entry("a", 7, "interrupted", "p")),
    ]);
    expect(s.entries.has("a")).toBe(false);
  });

  it("evicted then a stale (lower rev) upsert does not resurrect", () => {
    const s = ready([
      up(entry("a", 5, "final", "x")),
      { event: "entry_evicted", id: "a" },
      up(entry("a", 3, "partial", "x")),
    ]);
    expect(s.entries.has("a")).toBe(false);
  });

  it("cleared entry: evict + stale re-upsert does not bring it back into view", () => {
    let s = ready([up(entry("a", 5, "final", "x"))]);
    s = reduce(s, { type: "clear_view" });
    s = feed(s, [{ event: "entry_evicted", id: "a" }, up(entry("a", 5, "final", "x"))]);
    expect(visibleEntries(s).length).toBe(0);
  });

  it("interleaved pairing codes: ending the newer code does not hide a still-live older code", () => {
    let s = ready([conn("A", "pairing", "A"), conn("B", "pairing", "B")]);
    s = feed(s, [codeShown("A", "111111", 120), codeShown("B", "222222", 120)]);
    s = feed(s, [{ event: "pairing_code_ended", peer: "B", reason: "cancelled" }]);
    // A's code is still valid on A's phone; the user has no way to see it.
    expect(s.pairing?.code).toBe("111111");
  });

  it("pairing_code_ended / result for another peer leaves the modal alone", () => {
    let s = ready([codeShown("A", "111111", 120)]);
    s = feed(s, [
      { event: "pairing_code_ended", peer: "B", reason: "expired" },
      { event: "pairing_result", peer: "B", device_id: null, phone_name: null, ok: true, attempts_remaining: 0 },
    ]);
    expect(s.pairing?.code).toBe("111111");
  });

  it("pairing_result with attempts_remaining < 0 closes the modal", () => {
    let s = ready([codeShown("A", "111111", 120)]);
    s = feed(s, [
      { event: "pairing_result", peer: "A", device_id: null, phone_name: null, ok: false, attempts_remaining: -1 },
    ]);
    expect(s.pairing).toBeNull();
  });

  it("buffered code then buffered ended for that peer: snapshot's code is kept", () => {
    let s = feed(initialState(), [codeShown("A", "999999", 120), { event: "pairing_code_ended", peer: "A", reason: "expired" }]);
    s = feed(s, [
      snapshot([], [
        { peer: "A", state: "pairing", device_id: PHONE, name: "A", paired: false, pairing: { code: "123456", phone_name: "A", expires_in_secs: 60 } },
      ]),
    ]);
    expect(s.pairing?.code).toBe("123456");
  });

  it("config_changed persisted:false then true clears the not-saved flag", () => {
    const s = ready([
      { event: "config_changed", log_dir: "/a", name: "n", persisted: false },
      { event: "config_changed", log_dir: "/b", name: "n", persisted: true },
    ]);
    expect(s.configPersisted).toBe(true);
    expect(s.logDir).toBe("/b");
  });

  it("log_recovered without a prior warning is a no-op", () => {
    const s0 = ready();
    expect(feed(s0, [{ event: "log_recovered" }])).toBe(s0);
  });

  it("buffered log_warning then log_recovered replays to no warning", () => {
    let s = feed(initialState(), [{ event: "log_warning", message: "disk" }, { event: "log_recovered" }]);
    s = feed(s, [snapshot()]);
    expect(s.logWarning).toBeNull();
  });
});

// ================================================================ scale

describe("scale", () => {
  it("10k distinct upserts stay capped at 500 and keep the newest", () => {
    let s = ready();
    const t = performance.now();
    for (let i = 0; i < 10_000; i++) s = feed(s, [up(entry(`e${i}`, 1, "final", `t${i}`))]);
    const ms = performance.now() - t;
    expect(s.entries.size).toBe(MAX_ENTRIES);
    expect(s.order.length).toBe(MAX_ENTRIES);
    expect(s.order[0]).toBe("e9500");
    expect(ms).toBeLessThan(2000);
  });

  it("10k revisions of one partial stay a single entry", () => {
    let s = ready();
    for (let i = 1; i <= 10_000; i++) s = feed(s, [up(entry("p", i, "partial", "x".repeat(i % 100)))]);
    expect(s.entries.size).toBe(1);
    expect(s.order.length).toBe(1);
  });

  it("pre-snapshot buffer is bounded", () => {
    let s = initialState();
    for (let i = 0; i < 5000; i++) s = feed(s, [up(entry(`e${i}`, 1, "final", ""))]);
    expect(s.buffered.length).toBeLessThanOrEqual(2000);
    s = feed(s, [snapshot()]);
    expect(s.entries.size).toBeLessThanOrEqual(MAX_ENTRIES);
  });

  it("1k distinct pairing codes / notices keep bounded state", () => {
    let s = ready();
    for (let i = 0; i < 1000; i++) {
      s = feed(s, [
        codeShown(`p${i}`, String(100000 + i), 120),
        { event: "peer_error", peer: `p${i}`, code: "x", message: "m".repeat(1000), authenticated: false },
      ]);
    }
    expect(s.pairing?.peer).toBe("p999");
    expect(s.notices.length).toBe(MAX_NOTICES);
  });

  it("toolbar status text stays bounded with many connected phones", () => {
    let s = ready();
    for (let i = 0; i < 1000; i++) s = feed(s, [conn(`p${i}`, "hello_exchanged", `phone-${i}-${"n".repeat(50)}`)]);
    expect(connectionStatus(s, "mac").text.length).toBeLessThan(1000);
  });

  it("search over 500 x 32 KB entries completes in < 50 ms", () => {
    let s = ready();
    for (let i = 0; i < 500; i++) {
      s = feed(s, [up(entry(`e${i}`, 1, "final", "Lorem Ipsum ".repeat(2700).slice(0, 32_000)))]);
    }
    s = reduce(s, { type: "search", query: "needle" });
    visibleEntries(s); // warm
    const t = performance.now();
    const v = visibleEntries(s);
    const ms = performance.now() - t;
    expect(v.length).toBe(0);
    expect(ms).toBeLessThan(50);
  });

  it("search is case-insensitive for non-ASCII with length-changing lowercase", () => {
    // "İ".toLowerCase() is "i̇" (2 code units); the match must still work.
    expect(matchesSearch(entry("a", 1, "final", "İSTANBUL"), "istanbul")).toBe(true);
  });

  it("Clear view then edits re-show only the edited entry", () => {
    let s = ready([up(entry("a", 1, "final", "a")), up(entry("b", 1, "final", "b"))]);
    s = reduce(s, { type: "clear_view" });
    expect(entriesInView(s)).toBe(0);
    s = feed(s, [up(entry("a", 2, "edit", "a2")), up(entry("c", 1, "partial", "c"))]);
    expect(visibleEntries(s).map((e) => e.id)).toEqual(["a", "c"]);
  });
});

// ========================================================== formatting

describe("formatting", () => {
  it("countdown: negative clamps to 0:00", () => {
    expect(formatCountdown(-5000)).toBe("0:00");
    expect(formatCountdown(-Infinity)).toBe("0:00");
  });

  it("countdown: NaN does not render NaN", () => {
    expect(formatCountdown(NaN)).toMatch(/^\d+:\d\d$/);
  });

  it("countdown: Infinity does not render Infinity/NaN", () => {
    expect(formatCountdown(Infinity)).toMatch(/^\d+:\d\d$/);
  });

  it("countdown: huge values keep m:ss shape", () => {
    expect(formatCountdown(Number.MAX_SAFE_INTEGER)).toMatch(/^\d+:\d\d$/);
  });

  it("pairing modal with NaN/huge expiry still expires (not stuck open forever)", () => {
    for (const secs of [NaN, 1e308, 18446744073709551615]) {
      let s = ready([codeShown("A", "123456", secs)]);
      s = reduce(s, { type: "tick", now: T0 + 10 * 60_000 });
      expect(s.pairing, `expires_in_secs=${secs}`).toBeNull();
    }
  });

  it("clock skew: countdown never exceeds the code's lifetime after the wall clock jumps back", () => {
    const s = ready([codeShown("A", "123456", 120)]);
    const nowAfterJump = T0 - 3_600_000;
    const remaining = s.pairing!.deadline - nowAfterJump;
    expect(remaining).toBeLessThanOrEqual(120_000);
  });

  it("formatCode: 6 digits grouped, others returned unchanged", () => {
    expect(formatCode("123456")).toBe("123 456");
    for (const c of ["", "12345", "1234567", "12345a", " 123456", "１２３４５６", "<b>1</b>"]) {
      expect(formatCode(c)).toBe(c);
    }
  });

  it("formatCode rejects '123456\\n' (regex $ must not allow trailing newline)", () => {
    expect(formatCode("123456\n")).toBe("123456\n");
  });

  it("formatDate: extreme timestamps", () => {
    expect(formatDate(0)).toMatch(/^19(69|70)-\d\d-\d\d$/);
    expect(formatDate(18446744073709551615)).toBe("");
    expect(formatDate(NaN)).toBe("");
    expect(formatDate(-1)).toMatch(/^19(69|70)-\d\d-\d\d$/);
    // Year beyond 9999 or negative should not produce a malformed date string.
    expect(formatDate(8.64e15)).toMatch(/^\d{4}-\d\d-\d\d$|^$/);
    expect(formatDate(-8.64e15)).toMatch(/^\d{4}-\d\d-\d\d$|^$/);
  });
});

// ================================================================ copy

describe("copy", () => {
  it("copyText preserves CRLF, trailing newline, NUL and lone surrogates exactly", () => {
    const texts = ["a\r\nb\r\n", "trailing\n", "nul\u0000x", "lone\uD800x", "\uDC00", "  spaced  ", ""];
    for (const t of texts) {
      const s = ready([up(entry("a", 1, "final", t))]);
      expect(copyText(s.entries.get("a")!)).toBe(t);
    }
  });
});
