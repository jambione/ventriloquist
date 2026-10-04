import { afterEach, describe, expect, it, vi } from "vitest";
import {
  MAX_ENTRIES,
  copyText,
  currentEntry,
  entriesInView,
  initialState,
  reduce,
  visibleEntries,
  type Action,
  type AppState,
} from "./state";
import type { Entry, HostEvent, PeerStatus } from "./types";

const PHONE = "0f8fad5b-d9cb-469f-a165-70867728950e";

function entry(id: string, rev: number, state: Entry["state"], text: string): Entry {
  return {
    id,
    rev,
    state,
    text,
    ts: 1759500000000,
    device_id: PHONE,
    device_name: "Jon's iPhone",
    first_received_at: "2026-10-03T14:03:21+02:00",
    received_at: "2026-10-03T14:03:22+02:00",
    time: "14:03:22",
    partial: state === "partial",
    edited: state === "edit",
  };
}

function snapshot(over: Partial<Extract<HostEvent, { event: "snapshot" }>> = {}): HostEvent {
  return {
    event: "snapshot",
    device_id: "desk",
    name: "My Mac",
    log_dir: "/Users/me/Documents/Ventriloquist",
    paired_peers: [],
    adapter_state: "scanning",
    peers: [],
    entries: [],
    ...over,
  };
}

// Pairing deadlines use the monotonic clock (performance.now()); tests set it.
let clockNow = 0;
function setClock(ms: number): void {
  clockNow = ms;
  vi.spyOn(performance, "now").mockImplementation(() => clockNow);
}
afterEach(() => vi.restoreAllMocks());

const host = (event: HostEvent, now = 0): Action => ({ type: "host", event, now });
const up = (e: Entry): HostEvent => ({ event: "entry_upserted", entry: e });

function run(actions: Action[], s: AppState = initialState()): AppState {
  return actions.reduce(reduce, s);
}

function ready(...events: HostEvent[]): AppState {
  return run([host(snapshot()), ...events.map((e) => host(e))]);
}

const texts = (s: AppState): string[] => visibleEntries(s).map((e) => e.text);

describe("snapshot", () => {
  it("rebuilds the full state", () => {
    const peer: PeerStatus = {
      peer: "ble:x#1",
      state: "secure",
      device_id: PHONE,
      name: "Jon's iPhone",
      paired: true,
      pairing: null,
    };
    const s = run([
      host(
        snapshot({
          entries: [entry("a", 2, "final", "one"), entry("b", 0, "partial", "tw")],
          peers: [peer],
          paired_peers: [{ device_id: PHONE, name: "Jon's iPhone", public_key: "k", paired_at_ms: 1 }],
        }),
      ),
    ]);
    expect(s.phase).toBe("ready");
    expect(s.name).toBe("My Mac");
    expect(s.adapter).toBe("scanning");
    expect(texts(s)).toEqual(["one", "tw"]);
    expect(s.peers.get("ble:x#1")?.state).toBe("secure");
    expect(s.pairedPeers).toHaveLength(1);
  });

  it("buffers events that arrive before the snapshot and lets the snapshot win", () => {
    let s = run([
      host({ event: "adapter_state", state: "powered_off" }),
      host(up(entry("a", 1, "final", "old"))),
      host({ event: "log_warning", message: "disk full" }),
    ]);
    expect(s.phase).toBe("loading");
    expect(visibleEntries(s)).toEqual([]);
    s = reduce(s, host(snapshot({ entries: [entry("a", 2, "edit", "new")] })));
    expect(texts(s)).toEqual(["new"]);
    expect(s.adapter).toBe("scanning"); // superseded by the snapshot
    expect(s.logWarning).toBe("disk full"); // replayed
    expect(s.buffered).toEqual([]);
  });

  it("keeps a newer partial delivered ahead of the snapshot (outbox coalescing)", () => {
    const s = run([
      host(up(entry("a", 5, "partial", "hello wor"))),
      host(snapshot({ entries: [entry("a", 3, "partial", "hel")] })),
    ]);
    expect(texts(s)).toEqual(["hello wor"]);
    expect(s.entries.get("a")?.rev).toBe(5);
  });

  it("replays evictions in order", () => {
    const s = run([
      host(up(entry("a", 1, "final", "x"))),
      host({ event: "entry_evicted", id: "a" }),
      host(snapshot({ entries: [entry("b", 1, "final", "y")] })),
    ]);
    expect(texts(s)).toEqual(["y"]);
  });

  it("restores the pairing modal and prefers a newer code delivered ahead of it", () => {
    const withCode = snapshot({
      peers: [
        {
          peer: "p1",
          state: "pairing",
          device_id: PHONE,
          name: "Jon's iPhone",
          paired: false,
          pairing: { code: "111111", phone_name: "Jon's iPhone", expires_in_secs: 30 },
        },
      ],
    });
    setClock(1000);
    const restored = run([host(withCode, 1000)]);
    expect(restored.pairing).toMatchObject({ peer: "p1", code: "111111", deadline: 31000 });

    const shown: HostEvent = {
      event: "pairing_code_shown",
      peer: "p1",
      device_id: PHONE,
      phone_name: "Jon's iPhone",
      code: "222222",
      expires_in_secs: 120,
    };
    setClock(500);
    let newer = run([host(shown, 500)]);
    setClock(1000);
    newer = run([host(withCode, 1000)], newer);
    expect(newer.pairing).toMatchObject({ code: "222222", deadline: 120500 });

    setClock(500);
    let ended = run([
      host(shown, 500),
      host({ event: "pairing_code_ended", peer: "p1", reason: "expired" }, 600),
    ]);
    setClock(1000);
    ended = run([host(withCode, 1000)], ended);
    expect(ended.pairing?.code).toBe("111111");
  });

  it("a later snapshot rebuilds entries but keeps Clear view", () => {
    let s = ready(up(entry("a", 1, "final", "alpha")));
    s = reduce(s, { type: "clear_view" });
    s = reduce(
      s,
      host(snapshot({ entries: [entry("a", 1, "final", "alpha"), entry("b", 1, "final", "beta")] })),
    );
    expect(texts(s)).toEqual(["beta"]);
  });

  it("stays fatal", () => {
    const s = run([{ type: "fatal", message: "boom" }, host(snapshot())]);
    expect(s.phase).toBe("fatal");
    expect(s.fatal).toBe("boom");
  });
});

describe("entries", () => {
  it("partial → final → edited", () => {
    let s = ready(up(entry("a", 0, "partial", "kube")));
    expect(visibleEntries(s)[0]).toMatchObject({ partial: true, edited: false });
    s = reduce(s, host(up(entry("a", 1, "partial", "kubectl get"))));
    s = reduce(s, host(up(entry("a", 2, "final", "kubectl get pods"))));
    expect(visibleEntries(s)[0]).toMatchObject({ partial: false, edited: false, text: "kubectl get pods" });
    s = reduce(s, host(up(entry("a", 3, "edit", "kubectl get pods -A"))));
    expect(visibleEntries(s)).toHaveLength(1);
    expect(visibleEntries(s)[0]).toMatchObject({ edited: true, state: "edit", text: "kubectl get pods -A" });
  });

  it("ignores lower or equal revisions", () => {
    let s = ready(up(entry("a", 3, "edit", "new")));
    s = reduce(s, host(up(entry("a", 2, "final", "old"))));
    s = reduce(s, host(up(entry("a", 3, "final", "same rev"))));
    expect(texts(s)).toEqual(["new"]);
  });

  it("an interrupted partial (same rev) replaces the partial; a later final wins", () => {
    let s = ready(up(entry("a", 4, "partial", "half a sent")));
    s = reduce(s, host(up({ ...entry("a", 4, "interrupted", "half a sent"), partial: false })));
    expect(visibleEntries(s)[0]).toMatchObject({ state: "interrupted", partial: false });
    // interrupted twice, or a stale partial at the same rev: no change
    const again = reduce(s, host(up(entry("a", 4, "partial", "half a sent"))));
    expect(again).toBe(s);
    s = reduce(s, host(up(entry("a", 5, "final", "half a sentence"))));
    expect(visibleEntries(s)[0]).toMatchObject({ state: "final", text: "half a sentence" });
  });

  it("keeps first-arrival order and the newest at the bottom", () => {
    const s = ready(
      up(entry("a", 0, "partial", "1")),
      up(entry("b", 0, "final", "2")),
      up(entry("a", 1, "final", "1!")),
    );
    expect(texts(s)).toEqual(["1!", "2"]);
  });

  it("evicts", () => {
    const s = ready(up(entry("a", 1, "final", "x")), { event: "entry_evicted", id: "a" });
    expect(visibleEntries(s)).toEqual([]);
    expect(s.order).toEqual([]);
  });

  it("caps the history at 500 entries", () => {
    const events = Array.from({ length: MAX_ENTRIES + 3 }, (_, i) => up(entry(`id${i}`, 1, "final", `t${i}`)));
    const s = ready(...events);
    expect(s.order).toHaveLength(MAX_ENTRIES);
    expect(texts(s)[0]).toBe("t3");
  });

  it("copies the exact text, with no trailing newline added or whitespace trimmed", () => {
    const raw = "  echo 'a'\n\tls -la  ‮\u0007";
    const e = entry("a", 1, "final", raw);
    expect(copyText(e)).toBe(raw);
    expect(copyText(entry("b", 1, "final", "kubectl get pods")).endsWith("\n")).toBe(false);
  });
});

describe("clear view", () => {
  const base = (): AppState =>
    ready(
      up(entry("a", 1, "final", "Kubectl get pods")),
      up(entry("b", 1, "final", "git status")),
      up(entry("c", 1, "final", "KUBECTL logs")),
    );

  it("clear view hides what is on screen; new entries and new revisions show", () => {
    let s = reduce(base(), { type: "clear_view" });
    expect(visibleEntries(s)).toEqual([]);
    expect(entriesInView(s)).toBe(0);
    expect(s.entries.size).toBe(3); // nothing removed from the store
    s = reduce(s, host(up(entry("d", 1, "final", "new one"))));
    s = reduce(s, host(up(entry("b", 2, "edit", "git status -s"))));
    expect(texts(s)).toEqual(["git status -s", "new one"]);
  });

  it("a live partial cleared mid-utterance comes back with its next revision", () => {
    let s = ready(up(entry("a", 1, "partial", "spea")));
    s = reduce(s, { type: "clear_view" });
    expect(texts(s)).toEqual([]);
    s = reduce(s, host(up(entry("a", 2, "partial", "speaking"))));
    expect(texts(s)).toEqual(["speaking"]);
  });
});

describe("pairing modal", () => {
  const shown = (peer: string, code: string): HostEvent => ({
    event: "pairing_code_shown",
    peer,
    device_id: PHONE,
    phone_name: "Jon's iPhone",
    code,
    expires_in_secs: 120,
  });

  it("opens with a deadline and closes on expiry", () => {
    setClock(10_000);
    let s = run([host(snapshot()), host(shown("p1", "123456"), 10_000)]);
    expect(s.pairing).toMatchObject({ code: "123456", deadline: 130_000 });
    s = reduce(s, { type: "tick", now: 129_999 });
    expect(s.pairing).not.toBeNull();
    s = reduce(s, { type: "tick", now: 130_000 });
    expect(s.pairing).toBeNull();
  });

  it("shows one at a time: a new code replaces the old", () => {
    const s = ready(shown("p1", "111111"), shown("p2", "222222"));
    expect(s.pairing).toMatchObject({ peer: "p2", code: "222222" });
    // an end for the replaced peer does not close the current one
    const t = reduce(s, host({ event: "pairing_code_ended", peer: "p1", reason: "cancelled" }));
    expect(t.pairing?.peer).toBe("p2");
  });

  it("closes on success, keeps the code after a wrong attempt, closes when attempts run out", () => {
    const res = (ok: boolean, left: number): HostEvent => ({
      event: "pairing_result",
      peer: "p1",
      device_id: PHONE,
      phone_name: "Jon's iPhone",
      ok,
      attempts_remaining: left,
    });
    let s = ready(shown("p1", "123456"), res(false, 2));
    expect(s.pairing).toMatchObject({ code: "123456", attemptsRemaining: 2 });
    expect(reduce(s, host(res(true, 0))).pairing).toBeNull();
    s = reduce(s, host(res(false, 0)));
    expect(s.pairing).toBeNull();
  });

  it("closes on code end, disconnect, and local cancel", () => {
    const s = ready(shown("p1", "123456"));
    expect(reduce(s, host({ event: "pairing_code_ended", peer: "p1", reason: "expired" })).pairing).toBeNull();
    expect(
      reduce(
        s,
        host({
          event: "connection_status",
          peer: "p1",
          state: "closed",
          device_id: PHONE,
          name: "x",
          paired: false,
          reason: null,
        }),
      ).pairing,
    ).toBeNull();
    expect(reduce(s, { type: "dismiss_pairing" }).pairing).toBeNull();
  });
});

describe("warnings and settings", () => {
  it("log warning is cleared by log_recovered", () => {
    let s = ready({ event: "log_warning", message: "Permission denied" });
    expect(s.logWarning).toBe("Permission denied");
    s = reduce(s, host({ event: "log_recovered" }));
    expect(s.logWarning).toBeNull();
  });

  it("storage warnings and peer errors become dismissible notices (capped)", () => {
    let s = ready(
      { event: "storage_warning", message: "Could not save the settings: denied" },
      { event: "version_mismatch", peer: "p", device: "Jon's iPhone" },
    );
    expect(s.notices.map((n) => n.text)).toEqual([
      "Could not save the settings: denied",
      "Update Ventriloquist on \u2068Jon's iPhone\u2069",
    ]);
    const first = s.notices[0];
    if (first === undefined) throw new Error("no notice");
    s = reduce(s, { type: "dismiss_notice", id: first.id });
    expect(s.notices).toHaveLength(1);
    for (let i = 0; i < 10; i++) s = reduce(s, host({ event: "storage_warning", message: `w${i}` }));
    expect(s.notices).toHaveLength(5);
    expect(s.notices.at(-1)?.text).toBe("w9");
  });

  it("truncates long peer error messages", () => {
    const s = ready({ event: "peer_error", peer: "p", code: "x", message: "m".repeat(1000), authenticated: false });
    expect(Array.from(s.notices[0]?.text ?? "").length).toBeLessThan(260);
  });

  it("config_changed updates the settings and the persisted flag", () => {
    const s = ready({ event: "config_changed", log_dir: "/tmp/logs", name: "Desk", persisted: false });
    expect(s).toMatchObject({ logDir: "/tmp/logs", name: "Desk", configPersisted: false });
  });

  it("tracks connections and drops closed ones", () => {
    const cs = (state: "secure" | "closed"): HostEvent => ({
      event: "connection_status",
      peer: "p1",
      state,
      device_id: PHONE,
      name: "Jon's iPhone",
      paired: true,
      reason: null,
    });
    let s = ready(cs("secure"));
    expect(s.peers.size).toBe(1);
    s = reduce(s, host(cs("closed")));
    expect(s.peers.size).toBe(0);
  });
});

describe("review fixes", () => {
  it("a snapshot carries the log warning, so the banner survives a page reload (R2)", () => {
    const s = run([host(snapshot({ log_warning: "disk full (will retry)" }))]);
    expect(s.logWarning).toBe("disk full (will retry)");
    const none = run([host(snapshot({ log_warning: null }))]);
    expect(none.logWarning).toBeNull();
    // a buffered recovery that arrived before the snapshot still wins
    const recovered = run([host({ event: "log_recovered" }), host(snapshot({ log_warning: "x" }))]);
    expect(recovered.logWarning).toBeNull();
  });

  it("a late snapshot after ready does not bring back a recovered log warning", () => {
    const s = run([host(snapshot({ log_warning: "x" })), host({ event: "log_recovered" }), host(snapshot({ log_warning: "x" }))]);
    expect(s.logWarning).toBeNull();
  });

  it("tombstones are bounded", () => {
    let s = ready();
    for (let i = 0; i < 10_500; i++) s = reduce(s, host({ event: "entry_evicted", id: `x${i}` }));
    expect(s.evicted.size).toBe(10_000);
    expect(s.evicted.has("x0")).toBe(false);
    expect(s.evicted.has("x10499")).toBe(true);
  });

  it("a newer revision of an evicted entry is accepted again", () => {
    const s = ready(up(entry("a", 2, "final", "x")), { event: "entry_evicted", id: "a" }, up(entry("a", 3, "edit", "y")));
    expect(texts(s)).toEqual(["y"]);
  });
});

describe("devices seen", () => {
  it("follows devices_seen events and the snapshot", () => {
    let s = ready();
    expect(s.devicesSeen).toBe(0);
    s = reduce(s, host({ event: "devices_seen", count: 7 }));
    expect(s.devicesSeen).toBe(7);
    const fresh = reduce(initialState(), host(snapshot({ devices_seen: 9 })));
    expect(fresh.devicesSeen).toBe(9);
  });
});

describe("current dictation (regression: new dictations stopped appearing)", () => {
  const A = "aaaaaaaa-0000-4000-8000-000000000001";
  const B = "bbbbbbbb-0000-4000-8000-000000000002";
  const upsert = (e: Entry): HostEvent => ({ event: "entry_upserted", entry: e });
  const accepted = (e: Entry): HostEvent => ({ event: "final_accepted", entry: e });
  const noise: HostEvent[] = [
    { event: "log_warning", message: "disk full" },
    { event: "log_warning", message: "disk full" },
    { event: "log_recovered" },
    { event: "log_warning", message: "again" },
    { event: "log_recovered" },
  ];
  const dictateA = (): HostEvent[] => [
    upsert(entry(A, 0, "partial", "hel")),
    upsert(entry(A, 1, "partial", "hello wor")),
    upsert(entry(A, 2, "final", "hello world")),
    accepted(entry(A, 2, "final", "hello world")),
  ];
  const dictateB = (): HostEvent[] => [
    upsert(entry(B, 0, "partial", "se")),
    upsert(entry(B, 1, "final", "second")),
    accepted(entry(B, 1, "final", "second")),
  ];

  it("final_accepted does not break the reducer", () => {
    const s = ready(...dictateA());
    expect(s).toBeDefined();
    expect(currentEntry(s)?.text).toBe("hello world");
    // the state stays usable afterwards
    expect(reduce(s, host({ event: "log_recovered" }))).toBeDefined();
  });

  it("B replaces A as the current entry after warnings and recoveries", () => {
    const s = ready(...dictateA(), ...noise, ...dictateB());
    expect(currentEntry(s)?.id).toBe(B);
    expect(currentEntry(s)?.text).toBe("second");
    expect(texts(s)).toEqual(["hello world", "second"]);
  });

  it("B shows live partials as they arrive", () => {
    const s = ready(...dictateA(), ...noise, upsert(entry(B, 0, "partial", "se")));
    expect(currentEntry(s)?.id).toBe(B);
    expect(currentEntry(s)?.partial).toBe(true);
  });

  it("B is visible after Clear view between A and B", () => {
    let s = ready(...dictateA(), ...noise);
    s = reduce(s, { type: "clear_view" });
    expect(currentEntry(s)).toBeNull();
    s = run(dictateB().map((e) => host(e)), s);
    expect(currentEntry(s)?.id).toBe(B);
    expect(currentEntry(s)?.text).toBe("second");
  });

  it("Clear view during B's partials hides B only until its next revision", () => {
    let s = ready(...dictateA(), upsert(entry(B, 0, "partial", "se")));
    s = reduce(s, { type: "clear_view" });
    expect(currentEntry(s)).toBeNull();
    s = run(dictateB().map((e) => host(e)).slice(1), s);
    expect(currentEntry(s)?.text).toBe("second");
  });

  it("a NEWER utterance is never hidden by Clear view or by tombstones", () => {
    let s = ready(...dictateA());
    s = reduce(s, { type: "clear_view" });
    // a late, same-rev re-delivery of A stays hidden
    s = reduce(s, host(upsert(entry(A, 2, "final", "hello world"))));
    expect(currentEntry(s)).toBeNull();
    // an evicted A (tombstoned) then B arrives
    s = reduce(s, host({ event: "entry_evicted", id: A }));
    s = run(dictateB().map((e) => host(e)), s);
    expect(currentEntry(s)?.id).toBe(B);
  });

  it("survives a snapshot taken before B and events buffered across it", () => {
    let s = run([
      host(upsert(entry(B, 0, "partial", "se"))), // buffered, pre-snapshot
      host({ event: "log_warning", message: "x" }),
      host(snapshot({ entries: [entry(A, 2, "final", "hello world")] })),
    ]);
    expect(currentEntry(s)?.id).toBe(B);
    // a late duplicate snapshot does not change that
    s = reduce(s, host(snapshot({ entries: [entry(A, 2, "final", "hello world")] })));
    expect(currentEntry(s)?.id).toBe(B);
  });

  it("an unknown future event is ignored, never turns the state undefined", () => {
    const s = ready(...dictateA());
    const odd = { event: "something_new" } as unknown as HostEvent;
    expect(reduce(s, host(odd))).toBe(s);
  });
});

describe("phone app not open", () => {
  it("follows phone_app_not_open events and the snapshot", () => {
    let s = ready();
    expect(s.phoneAppNotOpen).toBe(false);
    s = reduce(s, host({ event: "phone_app_not_open", active: true }));
    expect(s.phoneAppNotOpen).toBe(true);
    s = reduce(s, host({ event: "phone_app_not_open", active: false }));
    expect(s.phoneAppNotOpen).toBe(false);
    expect(reduce(initialState(), host(snapshot({ phone_app_not_open: true }))).phoneAppNotOpen).toBe(true);
  });
});
