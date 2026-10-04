// Typed wrappers around the Tauri commands and the host event channel
// (desktop/app/src-tauri/src/lib.rs).

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { HostEvent } from "./types";

/** The single Tauri event that carries every `HostEvent` (typed JSON). */
export const HOST_EVENT = "host-event";

export const backend = {
  onHostEvent(handler: (ev: HostEvent) => void): Promise<UnlistenFn> {
    return listen<HostEvent>(HOST_EVENT, (e) => handler(e.payload));
  },
  /** Ask the host for a `snapshot` event. Rejects if the host is not running. */
  snapshot: (): Promise<void> => invoke("snapshot"),
  forgetPeer: (deviceId: string): Promise<void> => invoke("forget_peer", { deviceId }),
  setLogDir: (path: string): Promise<void> => invoke("set_log_dir", { path }),
  setName: (name: string): Promise<void> => invoke("set_name", { name }),
  cancelPairing: (peer: string): Promise<void> => invoke("cancel_pairing", { peer }),
  openLogFolder: (): Promise<void> => invoke("open_log_folder"),
  /** Folder picker; resolves to the chosen absolute path, or null. */
  pickLogDir: (): Promise<string | null> => invoke("pick_log_dir"),
  copyText: (text: string): Promise<void> => invoke("copy_text", { text }),
};
