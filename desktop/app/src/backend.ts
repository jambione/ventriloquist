// Typed wrappers around the Tauri commands and the host event channel
// (desktop/app/src-tauri/src/lib.rs).

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AccessibilityStatus,
  BindingNotice,
  DeliveryEvent,
  HostEvent,
  HotkeyView,
  Modifier,
  NewlineMode,
  RelaySettingsView,
  SlotsView,
  TestReport,
} from "./types";

/** The single Tauri event that carries every `HostEvent` (typed JSON). */
export const HOST_EVENT = "host-event";

export const backend = {
  onHostEvent(handler: (ev: HostEvent) => void): Promise<UnlistenFn> {
    return listen<HostEvent>(HOST_EVENT, (e) => handler(e.payload));
  },
  onDelivery(handler: (ev: DeliveryEvent) => void): Promise<UnlistenFn> {
    return listen<DeliveryEvent>("delivery", (e) => handler(e.payload));
  },
  onSlots(handler: (v: SlotsView) => void): Promise<UnlistenFn> {
    return listen<SlotsView>("slots", (e) => handler(e.payload));
  },
  onBindingNotice(handler: (n: BindingNotice) => void): Promise<UnlistenFn> {
    return listen<BindingNotice>("binding-notice", (e) => handler(e.payload));
  },
  /** Ask the host for a `snapshot` event. Rejects if the host is not running. */
  snapshot: (): Promise<void> => invoke("snapshot"),
  forgetPeer: (deviceId: string): Promise<void> => invoke("forget_peer", { deviceId }),
  /** Tell the host how many events were handled (flow control). */
  ackEvents: (count: number): Promise<void> => invoke("ack_events", { count }),
  setName: (name: string): Promise<void> => invoke("set_name", { name }),
  cancelPairing: (peer: string): Promise<void> => invoke("cancel_pairing", { peer }),
  openLogFolder: (): Promise<void> => invoke("open_log_folder"),
  /** Folder picker; the host itself sets the chosen folder as the log
   * folder. Resolves to false when the user cancelled. */
  pickLogDir: (): Promise<boolean> => invoke("pick_log_dir"),
  copyText: (text: string): Promise<void> => invoke("copy_text", { text }),
  slotsSnapshot: (): Promise<SlotsView> => invoke("slots_snapshot"),
  /** 0 = Off. */
  selectSlot: (slot: number): Promise<void> => invoke("select_slot", { slot }),
  unbindSlot: (slot: number): Promise<void> => invoke("unbind_slot", { slot }),
  /** Clear every binding; the active slot becomes Off. */
  clearAllSlots: (): Promise<void> => invoke("clear_all_slots"),
  appVersion: (): Promise<{ version: string; commit: string }> => invoke("app_version"),
  diagnosticsInfo: (): Promise<{ log_path: string | null; error: string | null }> =>
    invoke("diagnostics_info"),
  openDiagnosticsFile: (): Promise<void> => invoke("open_diagnostics_file"),
  openDiagnosticsFolder: (): Promise<void> => invoke("open_diagnostics_folder"),
  setSlotSettings: (
    slot: number,
    settings: { autoSubmit?: boolean; newlineMode?: NewlineMode; followTitleChanges?: boolean },
  ): Promise<void> =>
    invoke("set_slot_settings", {
      slot,
      autoSubmit: settings.autoSubmit ?? null,
      newlineMode: settings.newlineMode ?? null,
      followTitleChanges: settings.followTitleChanges ?? null,
    }),
  sendToActive: (entryId: string): Promise<void> => invoke("send_to_active", { entryId }),
  setHotkeyModifiers: (kind: "select" | "bind", modifiers: Modifier[]): Promise<HotkeyView> =>
    invoke("set_hotkey_modifiers", { kind, modifiers }),
  accessibilityStatus: (): Promise<AccessibilityStatus> => invoke("accessibility_status"),
  openAccessibilitySettings: (): Promise<void> => invoke("open_accessibility_settings"),
  // ---- relay (SPEC_V3 §6)
  relaySettings: (): Promise<RelaySettingsView> => invoke("relay_settings"),
  setRelayUrl: (url: string): Promise<RelaySettingsView> => invoke("set_relay_url", { url }),
  /** An empty token clears it. */
  setOwnerToken: (token: string): Promise<RelaySettingsView> => invoke("set_owner_token", { token }),
  /** Makes, stores and returns a new owner token (shown once). */
  generateOwnerToken: (): Promise<string> => invoke("generate_owner_token"),
  testRelay: (): Promise<TestReport> => invoke("test_relay"),
  resetRelayRoom: (): Promise<void> => invoke("reset_relay_room"),
  /** "Add phone": the host answers with `phone_pairing_qr` events. */
  startPhonePairing: (): Promise<void> => invoke("start_phone_pairing"),
  stopPhonePairing: (): Promise<void> => invoke("stop_phone_pairing"),
  /** The QR for a pairing URI as an SVG data: URL, rendered locally. */
  qrSvg: (uri: string): Promise<string> => invoke("qr_svg", { uri }),
};
