//! Pure, unit-tested connection policies shared by the transports and the
//! session manager.

use std::time::Duration;

use vq_protocol::{FALLBACK_MTU, MIN_MTU};

/// Largest reconnect backoff (SPEC §6.3).
pub const MAX_BACKOFF: Duration = Duration::from_secs(15);

/// An unpaired (not Secure) phone is dropped after this long without
/// pairing activity (SPEC §6.3).
pub const IDLE_DROP_AFTER: Duration = Duration::from_secs(5 * 60);

/// After an idle drop, the transport waits this long before reconnecting
/// to the same phone (see docs/SPEC_QUESTIONS.md, M3).
pub const IDLE_RECONNECT_HOLDOFF: Duration = Duration::from_secs(60);

/// After sending `error{unknown_peer}`, the transport waits this long
/// before reconnecting to the same phone.
pub const UNKNOWN_PEER_RECONNECT_HOLDOFF: Duration = Duration::from_secs(30);

/// Reconnect delay after `failures` consecutive failed or dropped
/// connections: 0 → immediately, then 1, 2, 4, 8, and 15 s from then on.
pub fn backoff_delay(failures: u32) -> Duration {
    match failures {
        0 => Duration::ZERO,
        1..=4 => Duration::from_secs(1 << (failures - 1)),
        _ => MAX_BACKOFF,
    }
}

/// Delay before the next attempt: the backoff, or a longer hold-off the
/// session layer asked for.
pub fn next_attempt_delay(failures: u32, holdoff: Option<Duration>) -> Duration {
    backoff_delay(failures).max(holdoff.unwrap_or(Duration::ZERO))
}

/// Frame `mtu` on BLE from the negotiated ATT MTU (README §2): ATT MTU − 3,
/// or 20 when the MTU is unknown (0) or that would be below 20.
pub fn ble_frame_mtu(att_mtu: u16) -> usize {
    let usable = usize::from(att_mtu).saturating_sub(3);
    if usable < MIN_MTU {
        FALLBACK_MTU
    } else {
        usable
    }
}

/// Whether a connection should be dropped for pairing inactivity: only
/// peers that are not Secure, after [`IDLE_DROP_AFTER`] without pairing
/// activity (connect, `hello`, `pair_request`, `pair_confirm`).
pub fn idle_drop_due(secure: bool, last_pairing_activity: Duration, now: Duration) -> bool {
    !secure && now.saturating_sub(last_pairing_activity) >= IDLE_DROP_AFTER
}

/// The local name the iOS app advertises. iOS may move the 128-bit service
/// UUID into the scan response or the overflow area, so a device with this
/// name is also treated as a candidate.
pub const BLE_LOCAL_NAME: &str = "Ventriloquist";

/// A name-only candidate that turned out not to have the Ventriloquist GATT
/// service is not tried again *by name* for this long. Kept short: the iPhone
/// removes its service while the app is in the background, and the user
/// expects a reconnect within seconds of reopening it. Any advertisement that
/// carries the service UUID bypasses the block.
pub const NAME_ONLY_BLOCK: Duration = Duration::from_secs(20);

/// Every discovered device is logged at most once per id per this long.
pub const DEVICE_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Whether an advertisement is from (probably) a Ventriloquist phone: it
/// advertises [`vq_protocol::SERVICE_UUID`] **or** its local name is
/// [`BLE_LOCAL_NAME`].
pub fn is_candidate(services: &[uuid::Uuid], local_name: Option<&str>) -> bool {
    services.contains(&vq_protocol::SERVICE_UUID) || local_name == Some(BLE_LOCAL_NAME)
}

/// A candidate with the name but not the service UUID in its advertisement:
/// the GATT service must be verified after connecting.
pub fn is_name_only(services: &[uuid::Uuid], local_name: Option<&str>) -> bool {
    is_candidate(services, local_name) && !services.contains(&vq_protocol::SERVICE_UUID)
}

/// Whether a device last logged `since_last_log` ago (None: never) is logged
/// again.
pub fn device_log_due(since_last_log: Option<Duration>) -> bool {
    since_last_log.is_none_or(|d| d >= DEVICE_LOG_INTERVAL)
}

/// A BLE peripheral slot (rotating private addresses make every
/// advertisement look like a new device) is forgotten when it has not been
/// seen advertising, nor been connected, for this long.
pub const BLE_SLOT_TTL: Duration = Duration::from_secs(3 * 60);

/// Whether a BLE slot should be dropped: not connected (or connecting) and
/// not seen for [`BLE_SLOT_TTL`].
pub fn ble_slot_expired(active: bool, since_last_seen: Duration) -> bool {
    !active && since_last_seen >= BLE_SLOT_TTL
}

/// How often a failed `start_scan` is retried while the adapter is on.
pub const SCAN_RETRY: Duration = Duration::from_secs(1);

/// Whether to retry starting the scan now.
pub fn scan_retry_due(powered_on: bool, scanning: bool, since_last_attempt: Duration) -> bool {
    powered_on && !scanning && since_last_attempt >= SCAN_RETRY
}

/// While the adapter is not scanning because its state is unknown (e.g.
/// Bluetooth permission not granted yet on first run) the adapter is
/// re-acquired this often, so a later grant is noticed.
pub const ADAPTER_REACQUIRE_AFTER: Duration = Duration::from_secs(5);

/// Whether to drop the adapter and acquire a new one. Only when there is no
/// live adapter in use: on macOS every `Manager::adapters()` call creates a
/// new CoreBluetooth central, and dropping the old one while a connection
/// still uses it makes btleplug log "Event receiver died" / "Shouldn't get
/// anything but Ok!" and fail every later call on that peripheral with
/// "Device not found" (docs/SPEC_QUESTIONS.md v2 N3, R16).
pub fn adapter_reacquire_due(
    state_unknown: bool,
    scanning: bool,
    since: Duration,
    live_connections: usize,
) -> bool {
    state_unknown && !scanning && live_connections == 0 && since >= ADAPTER_REACQUIRE_AFTER
}

/// Record a sighting of `id` and return the number of **unique** ids seen
/// (the toolbar "devices seen" counter counts devices, not advertisements).
pub fn note_seen<T: std::hash::Hash + Eq>(seen: &mut std::collections::HashSet<T>, id: T) -> u64 {
    seen.insert(id);
    seen.len() as u64
}

/// Polling mode (v2.2): sleep between TX reads when the last read was empty.
pub const POLL_IDLE: Duration = Duration::from_millis(50);

/// How long to wait before the next TX read: none after a read that returned
/// data, [`POLL_IDLE`] after an empty one.
pub fn poll_wait(read_len: usize) -> Duration {
    if read_len == 0 {
        POLL_IDLE
    } else {
        Duration::ZERO
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vq_protocol::SERVICE_UUID;

    #[test]
    fn candidate_by_service_or_by_name() {
        let other = uuid::Uuid::from_u128(1);
        assert!(is_candidate(&[SERVICE_UUID], None));
        assert!(is_candidate(&[other, SERVICE_UUID], Some("Something")));
        assert!(is_candidate(&[], Some("Ventriloquist")));
        assert!(is_candidate(&[other], Some("Ventriloquist")));
        assert!(!is_candidate(&[], None));
        assert!(!is_candidate(&[other], Some("ventriloquist")));
        assert!(!is_candidate(&[other], Some("Ventriloquist 2")));
        assert!(!is_candidate(&[], Some("")));
    }

    #[test]
    fn name_only_means_candidate_without_the_uuid() {
        assert!(is_name_only(&[], Some("Ventriloquist")));
        assert!(!is_name_only(&[SERVICE_UUID], Some("Ventriloquist")));
        assert!(!is_name_only(&[SERVICE_UUID], None));
        assert!(!is_name_only(&[], Some("Other")));
    }

    #[test]
    fn device_logging_is_once_per_minute() {
        assert!(device_log_due(None));
        assert!(!device_log_due(Some(Duration::from_secs(59))));
        assert!(device_log_due(Some(Duration::from_secs(60))));
    }

    #[test]
    fn backoff_schedule() {
        let secs: Vec<u64> = (0..8).map(|n| backoff_delay(n).as_secs()).collect();
        assert_eq!(secs, vec![0, 1, 2, 4, 8, 15, 15, 15]);
        assert_eq!(backoff_delay(u32::MAX), MAX_BACKOFF);
        assert_eq!(
            next_attempt_delay(1, Some(Duration::from_secs(60))),
            Duration::from_secs(60)
        );
        assert_eq!(
            next_attempt_delay(5, Some(Duration::from_secs(3))),
            MAX_BACKOFF
        );
        assert_eq!(next_attempt_delay(2, None), Duration::from_secs(2));
    }

    #[test]
    fn ble_mtu() {
        assert_eq!(ble_frame_mtu(0), 20);
        assert_eq!(ble_frame_mtu(23), 20);
        assert_eq!(ble_frame_mtu(10), 20);
        assert_eq!(ble_frame_mtu(24), 21);
        assert_eq!(ble_frame_mtu(185), 182);
        assert_eq!(ble_frame_mtu(517), 514);
    }

    #[test]
    fn idle_drop() {
        let s = Duration::from_secs;
        assert!(!idle_drop_due(false, s(10), s(10 + 299)));
        assert!(idle_drop_due(false, s(10), s(10 + 300)));
        assert!(!idle_drop_due(true, s(0), s(100_000)));
        assert!(!idle_drop_due(false, s(50), s(10)));
    }

    #[test]
    fn ble_slot_expiry() {
        let s = Duration::from_secs;
        assert!(!ble_slot_expired(false, s(179)));
        assert!(ble_slot_expired(false, s(180)));
        assert!(!ble_slot_expired(true, s(10_000)), "connected slots stay");
    }

    #[test]
    fn scan_retry() {
        let ms = Duration::from_millis;
        assert!(scan_retry_due(true, false, ms(1000)));
        assert!(!scan_retry_due(true, false, ms(999)));
        assert!(!scan_retry_due(true, true, ms(5000)));
        assert!(!scan_retry_due(false, false, ms(5000)));
    }

    #[test]
    fn adapter_reacquire() {
        let s = Duration::from_secs;
        assert!(adapter_reacquire_due(true, false, s(5), 0));
        assert!(!adapter_reacquire_due(true, false, s(4), 0));
        assert!(!adapter_reacquire_due(true, true, s(60), 0));
        assert!(!adapter_reacquire_due(false, false, s(60), 0));
    }

    /// R16: the adapter a connection uses is never replaced under it.
    #[test]
    fn adapter_is_never_reacquired_while_a_connection_is_live() {
        let s = Duration::from_secs;
        for live in 1..4 {
            assert!(!adapter_reacquire_due(true, false, s(600), live), "live={live}");
        }
        assert!(adapter_reacquire_due(true, false, s(600), 0));
    }

    #[test]
    fn devices_seen_counts_unique_ids() {
        let mut seen = std::collections::HashSet::new();
        assert_eq!(note_seen(&mut seen, "a"), 1);
        assert_eq!(note_seen(&mut seen, "a"), 1);
        assert_eq!(note_seen(&mut seen, "b"), 2);
        assert_eq!(note_seen(&mut seen, "a"), 2);
    }

    #[test]
    fn poll_wait_pacing() {
        assert_eq!(poll_wait(0), Duration::from_millis(50));
        assert_eq!(poll_wait(1), Duration::ZERO);
        assert_eq!(poll_wait(512), Duration::ZERO);
    }
}
