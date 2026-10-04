import { describe, expect, it } from "vitest";
import {
  canSendToActive,
  deliveryBadge,
  formatHotkey,
  modifierChoices,
  slotChips,
  takenText,
} from "./format";
import { MAX_DELIVERIES, initialState, reduce, type AppState } from "./state";
import type { DeliveryEvent, SlotsView } from "./types";


function view(over: Partial<SlotsView> = {}): SlotsView {
  return { active: 0, slots: [], hotkeys: { select: ["ctrl", "shift"], bind: ["ctrl", "alt", "shift"], select_taken: [], bind_taken: [] }, ...over };
}

function slot(n: number, over: object = {}) {
  return {
    slot: n,
    app_name: "Teams",
    window_title: "Chat",
    element_role: "AXTextArea",
    status: "live" as const,
    auto_submit: false,
    newline_mode: null,
    follow_title_changes: false,
    ...over,
  };
}

function delivery(id: string, over: Partial<DeliveryEvent> = {}): DeliveryEvent {
  return {
    entry_id: id,
    slot: 2,
    app_name: "Teams",
    status: "sent",
    reason: null,
    method: "type",
    manual: false,
    ...over,
  };
}

const run = (s: AppState, ...actions: Parameters<typeof reduce>[1][]): AppState =>
  actions.reduce(reduce, s);

describe("slot bar reducer", () => {
  it("applies slots events and drops deliveries from them", () => {
    const s = run(initialState(), { type: "slots", view: view({ active: 2, slots: [slot(2)] }) });
    expect(s.slots?.active).toBe(2);
    expect(s.slots?.slots).toHaveLength(1);
  });

  it("snapshot merges deliveries but never regresses a result to sending", () => {
    let s = run(initialState(), { type: "delivery", event: delivery("a", { status: "sent" }) });
    s = run(s, {
      type: "slots_snapshot",
      view: view({ deliveries: [delivery("a", { status: "sending" }), delivery("b", { status: "off", slot: null })] }),
    });
    expect(s.deliveries.get("a")?.status).toBe("sent");
    expect(s.deliveries.get("b")?.status).toBe("off");
  });

  it("keeps at most MAX_DELIVERIES results, oldest dropped", () => {
    let s = initialState();
    for (let i = 0; i < MAX_DELIVERIES + 5; i++) s = run(s, { type: "delivery", event: delivery(`e${i}`) });
    expect(s.deliveries.size).toBe(MAX_DELIVERIES);
    expect(s.deliveries.has("e0")).toBe(false);
    expect(s.deliveries.has(`e${MAX_DELIVERIES + 4}`)).toBe(true);
  });

  it("a missing target raises one notice (not repeated), isolated app name", () => {
    const ev = delivery("a", { status: "missing", app_name: "Te‮ams" });
    const s = run(initialState(), { type: "delivery", event: ev }, { type: "delivery", event: { ...ev, entry_id: "b" } });
    expect(s.notices).toHaveLength(1);
    expect(s.notices[0]!.text).toBe("Slot 2 (⁨Teams⁩) not found — not sent");
  });

  it("a blocked or failed delivery raises a notice that says why", () => {
    const b = delivery("a", { status: "blocked", reason: "window changed: was 'x', now 'y'" });
    const f = delivery("b", { status: "failed", reason: "interrupted by user input" });
    const s = run(initialState(), { type: "delivery", event: b }, { type: "delivery", event: f });
    expect(s.notices).toHaveLength(2);
    expect(s.notices[0]!.text).toContain("blocked");
    expect(s.notices[0]!.text).toContain("window changed");
    expect(s.notices[1]!.text).toContain("not sent");
    expect(s.notices[1]!.text).toContain("interrupted by user input");
  });

  it("binding notices: accessibility flips the status, details are isolated", () => {
    let s = run(initialState(), {
      type: "binding_notice",
      notice: { code: "accessibility_needed", slot: 3, detail: null },
    });
    expect(s.accessibility).toEqual({ supported: true, trusted: false });
    expect(s.notices[0]!.text).toContain("Accessibility permission needed");
    s = run(s, { type: "binding_notice", notice: { code: "bind_failed", slot: 1, detail: "a‮b" } });
    expect(s.notices[1]!.text).toBe("Slot 1: not bound: ⁨ab⁩");
  });

  it("accessibility status is stable when unchanged", () => {
    const a = run(initialState(), { type: "accessibility", status: { supported: true, trusted: true } });
    expect(reduce(a, { type: "accessibility", status: { supported: true, trusted: true } })).toBe(a);
  });
});

describe("slot chips", () => {
  it("shows Off plus 1-9, dimming empty ones, highlighting the active", () => {
    const chips = slotChips(view({ active: 2, slots: [slot(2), slot(4, { status: "unverified", auto_submit: true }), slot(5, { status: "unbound" })] }));
    expect(chips).toHaveLength(10);
    expect(chips[0]!.label).toBe("Off");
    expect(chips[2]!.active).toBe(true);
    expect(chips[2]!.label).toBe("2 · ⁨Teams⁩ — ⁨Chat⁩");
    expect(chips[1]!.bound).toBe(false);
    expect(chips[4]).toMatchObject({ unverified: true, autoSubmit: true });
    expect(chips[5]).toMatchObject({ unbound: true });
    expect(slotChips(null)[0]!.active).toBe(true);
  });

  it("clips long labels but not tooltips", () => {
    const long = "x".repeat(100);
    const c = slotChips(view({ slots: [slot(1, { window_title: long })] }))[1]!;
    expect(c.label.length).toBeLessThan(60);
    expect(c.tooltip).toContain("x".repeat(100).slice(0, 100));
  });
});

describe("delivery badge", () => {
  it("renders every state", () => {
    expect(deliveryBadge(undefined)).toBeNull();
    expect(deliveryBadge(delivery("a"))).toEqual({ tone: "ok", text: "→ 2 · ⁨Teams⁩ ✓" });
    expect(deliveryBadge(delivery("a", { status: "sending" }))?.text).toBe("sending…");
    expect(deliveryBadge(delivery("a", { status: "off", slot: null }))?.text).toBe("not sent (Off)");
    expect(deliveryBadge(delivery("a", { status: "missing" }))?.text).toBe("✗ slot 2 missing");
    expect(deliveryBadge(delivery("a", { status: "blocked", reason: "secure text field" }))?.text).toBe(
      "⚠ blocked (⁨secure text field⁩)",
    );
    expect(deliveryBadge(delivery("a", { status: "failed", reason: "focus changed" }))?.text).toBe(
      "✗ failed: ⁨focus changed⁩",
    );
  });
});

describe("send to active slot and settings helpers", () => {
  it("is disabled when Off and for partials", () => {
    expect(canSendToActive(view({ active: 0 }), "final")).toBe(false);
    expect(canSendToActive(view({ active: 1 }), "final")).toBe(true);
    expect(canSendToActive(view({ active: 1 }), "edit")).toBe(true);
    expect(canSendToActive(view({ active: 1 }), "partial")).toBe(false);
    expect(canSendToActive(view({ active: 1 }), "interrupted")).toBe(false);
    expect(canSendToActive(null, "final")).toBe(false);
  });

  it("labels modifiers per platform (Windows has Alt/Win, mac Option/Cmd)", () => {
    expect(modifierChoices("mac").map((c) => c.label)).toEqual(["Ctrl", "Option", "Shift", "Cmd"]);
    expect(modifierChoices("windows").map((c) => c.label)).toEqual(["Ctrl", "Alt", "Shift", "Win"]);
    expect(formatHotkey(["ctrl", "alt", "shift"], "1–9", "mac")).toBe("Ctrl+Option+Shift+1–9");
    expect(formatHotkey(["ctrl", "alt", "shift"], "1–9", "windows")).toBe("Ctrl+Alt+Shift+1–9");
    expect(takenText([])).toBe("");
    expect(takenText([0, 3])).toBe("taken by another app: 0, 3");
  });
});
