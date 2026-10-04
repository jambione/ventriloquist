// Wire shapes of the host events (desktop/core/README.md, `HostEvent` in
// desktop/core/src/events.rs). Every string that came from a phone (text,
// names, error messages) is untrusted: render it with textContent only.

export type EntryState = "partial" | "final" | "edit" | "interrupted";

export interface Entry {
  id: string;
  rev: number;
  state: EntryState;
  text: string;
  ts: number;
  device_id: string;
  device_name: string;
  first_received_at: string;
  received_at: string;
  time: string;
  partial: boolean;
  edited: boolean;
}

export type PeerState = "connected" | "hello_exchanged" | "pairing" | "secure" | "closed";

export type AdapterState = "unknown" | "no_adapter" | "powered_off" | "unauthorized" | "scanning";

export type CodeEndReason = "expired" | "too_many_failures" | "cancelled" | "disconnected";

export interface PairedPeer {
  device_id: string;
  name: string;
  public_key: string;
  paired_at_ms: number;
}

export interface PairingStatus {
  code: string;
  phone_name: string;
  expires_in_secs: number;
}

export interface PeerStatus {
  peer: string;
  state: PeerState;
  device_id: string | null;
  name: string | null;
  paired: boolean;
  pairing: PairingStatus | null;
}

export type HostEvent =
  | { event: "started"; device_id: string; name: string; log_dir: string; paired_peers: PairedPeer[] }
  | {
      event: "snapshot";
      device_id: string;
      name: string;
      log_dir: string;
      paired_peers: PairedPeer[];
      adapter_state: AdapterState;
      peers: PeerStatus[];
      entries: Entry[];
      /** Latest log-write warning while the log is failing, else null. */
      log_warning?: string | null;
    }
  | { event: "entry_upserted"; entry: Entry }
  | { event: "entry_evicted"; id: string }
  | {
      event: "connection_status";
      peer: string;
      state: PeerState;
      device_id: string | null;
      name: string | null;
      paired: boolean;
      reason: string | null;
    }
  | {
      event: "pairing_code_shown";
      peer: string;
      device_id: string;
      phone_name: string;
      code: string;
      expires_in_secs: number;
    }
  | { event: "pairing_code_ended"; peer: string; reason: CodeEndReason }
  | {
      event: "pairing_result";
      peer: string;
      device_id: string | null;
      phone_name: string | null;
      ok: boolean;
      attempts_remaining: number;
    }
  | { event: "paired_peers_changed"; peers: PairedPeer[] }
  | { event: "peer_error"; peer: string; code: string; message: string; authenticated: boolean }
  | { event: "version_mismatch"; peer: string; device: string }
  | { event: "message_rejected"; peer: string; code: string }
  | { event: "log_warning"; message: string }
  | { event: "log_recovered" }
  | { event: "storage_warning"; message: string }
  | { event: "adapter_state"; state: AdapterState }
  | { event: "config_changed"; log_dir: string; name: string; persisted: boolean };
