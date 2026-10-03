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

#[cfg(test)]
mod tests {
    use super::*;

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
}
