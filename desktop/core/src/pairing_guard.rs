//! Pairing rate limits and lockout (README §7.3 "Pairing rate limits";
//! docs/SPEC_QUESTIONS.md D10). Pure: every method takes the monotonic
//! time `now`, so the policy is tested without sleeping.
//!
//! * Per device: at most one accepted `pair_request` per
//!   [`PAIR_REQUEST_MIN_INTERVAL`]; more than [`PAIR_REQUESTS_PER_WINDOW`]
//!   requests within [`PAIR_REQUEST_WINDOW`] refuse the device for
//!   [`DEVICE_REFUSAL`].
//! * Global: each code invalidated by 3 failures starts a lockout of
//!   [`lockout_duration`] (30 s, doubling, max 1 h); a successful pairing
//!   resets it.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use uuid::Uuid;

/// Minimum time between two accepted `pair_request`s of one device.
pub const PAIR_REQUEST_MIN_INTERVAL: Duration = Duration::from_secs(10);
/// Window for [`PAIR_REQUESTS_PER_WINDOW`].
pub const PAIR_REQUEST_WINDOW: Duration = Duration::from_secs(10 * 60);
/// `pair_request`s (accepted or not) one device may send per window.
pub const PAIR_REQUESTS_PER_WINDOW: usize = 5;
/// How long a device that exceeded the window limit is refused.
pub const DEVICE_REFUSAL: Duration = Duration::from_secs(10 * 60);
/// First global lockout after a code invalidation.
pub const LOCKOUT_BASE: Duration = Duration::from_secs(30);
/// Longest global lockout.
pub const LOCKOUT_MAX: Duration = Duration::from_secs(60 * 60);
/// Devices tracked at most (oldest activity is forgotten first).
pub const MAX_TRACKED_DEVICES: usize = 1024;

/// Global lockout after the `n`-th code invalidation since the last
/// successful pairing (`n` ≥ 1): 30 s, 60 s, 120 s, … capped at 1 h.
pub fn lockout_duration(n: u32) -> Duration {
    let shift = n.saturating_sub(1).min(16);
    LOCKOUT_BASE
        .saturating_mul(1u32 << shift)
        .min(LOCKOUT_MAX)
}

/// What to do with one `pair_request`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairRequestVerdict {
    /// Go ahead (still subject to the one-modal rule).
    Allow,
    /// `error{rate_limited}`, keep the connection.
    RateLimited,
    /// `error{rate_limited}` and disconnect; the device stays refused for
    /// the given time.
    Refuse(Duration),
}

#[derive(Debug, Default)]
struct DeviceHistory {
    requests: VecDeque<Duration>,
    last_accepted: Option<Duration>,
}

/// Pairing rate-limit state shared by all connections.
#[derive(Debug, Default)]
pub struct PairingGuard {
    devices: HashMap<Uuid, DeviceHistory>,
    refused: HashMap<Uuid, Duration>,
    invalidations: u32,
    locked_until: Option<Duration>,
}

impl PairingGuard {
    /// A guard with no history.
    pub fn new() -> Self {
        Self::default()
    }

    /// Remaining refusal time of `device`, if it is refused.
    pub fn refused_for(&self, device: &Uuid, now: Duration) -> Option<Duration> {
        self.refused
            .get(device)
            .and_then(|until| until.checked_sub(now))
            .filter(|d| !d.is_zero())
    }

    /// Remaining global lockout, if any.
    pub fn locked_for(&self, now: Duration) -> Option<Duration> {
        self.locked_until
            .and_then(|until| until.checked_sub(now))
            .filter(|d| !d.is_zero())
    }

    /// Record one `pair_request` from `device` and judge it.
    pub fn on_pair_request(&mut self, device: Uuid, now: Duration) -> PairRequestVerdict {
        if let Some(d) = self.refused_for(&device, now) {
            return PairRequestVerdict::Refuse(d);
        }
        if !self.devices.contains_key(&device) && self.devices.len() >= MAX_TRACKED_DEVICES {
            self.prune(now);
            self.evict_oldest();
        }
        let h = self.devices.entry(device).or_default();
        h.requests.push_back(now);
        while h
            .requests
            .front()
            .is_some_and(|t| now.saturating_sub(*t) >= PAIR_REQUEST_WINDOW)
        {
            h.requests.pop_front();
        }
        if h.requests.len() > PAIR_REQUESTS_PER_WINDOW {
            self.devices.remove(&device);
            self.refused.insert(device, now + DEVICE_REFUSAL);
            return PairRequestVerdict::Refuse(DEVICE_REFUSAL);
        }
        if h
            .last_accepted
            .is_some_and(|t| now.saturating_sub(t) < PAIR_REQUEST_MIN_INTERVAL)
        {
            return PairRequestVerdict::RateLimited;
        }
        if self.locked_for(now).is_some() {
            return PairRequestVerdict::RateLimited;
        }
        PairRequestVerdict::Allow
    }

    /// A code was minted for `device`.
    pub fn on_code_issued(&mut self, device: Uuid, now: Duration) {
        self.devices.entry(device).or_default().last_accepted = Some(now);
    }

    /// A code was invalidated by too many failures: start or extend the
    /// global lockout.
    pub fn on_code_invalidated(&mut self, now: Duration) {
        self.invalidations = self.invalidations.saturating_add(1);
        self.locked_until = Some(now + lockout_duration(self.invalidations));
    }

    /// A pairing succeeded: the lockout and its escalation are reset.
    pub fn on_paired(&mut self) {
        self.invalidations = 0;
        self.locked_until = None;
    }

    /// Forget history that no longer matters.
    pub fn prune(&mut self, now: Duration) {
        self.refused.retain(|_, until| *until > now);
        self.devices.retain(|_, h| {
            let last = h.requests.back().copied().max(h.last_accepted);
            last.is_some_and(|t| now.saturating_sub(t) < PAIR_REQUEST_WINDOW)
        });
    }

    fn evict_oldest(&mut self) {
        while self.devices.len() >= MAX_TRACKED_DEVICES {
            let oldest = self
                .devices
                .iter()
                .min_by_key(|(_, h)| h.requests.back().copied().max(h.last_accepted))
                .map(|(id, _)| *id);
            match oldest {
                Some(id) => {
                    self.devices.remove(&id);
                }
                None => break,
            }
        }
    }

    /// Number of devices with tracked history (tests).
    pub fn tracked_devices(&self) -> usize {
        self.devices.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: fn(u64) -> Duration = Duration::from_secs;

    #[test]
    fn lockout_doubles_and_caps() {
        let secs: Vec<u64> = (1..=9).map(|n| lockout_duration(n).as_secs()).collect();
        assert_eq!(secs, vec![30, 60, 120, 240, 480, 960, 1920, 3600, 3600]);
        assert_eq!(lockout_duration(u32::MAX), LOCKOUT_MAX);
        assert_eq!(lockout_duration(0), LOCKOUT_BASE);
    }

    #[test]
    fn min_interval_counts_from_the_last_accepted_request() {
        let mut g = PairingGuard::new();
        let d = Uuid::new_v4();
        assert_eq!(g.on_pair_request(d, S(0)), PairRequestVerdict::Allow);
        g.on_code_issued(d, S(0));
        assert_eq!(g.on_pair_request(d, S(9)), PairRequestVerdict::RateLimited);
        assert_eq!(g.on_pair_request(d, S(10)), PairRequestVerdict::Allow);
        // another device is not affected
        assert_eq!(
            g.on_pair_request(Uuid::new_v4(), S(10)),
            PairRequestVerdict::Allow
        );
    }

    #[test]
    fn sixth_request_in_window_refuses_for_10_minutes() {
        let mut g = PairingGuard::new();
        let d = Uuid::new_v4();
        for i in 0..5 {
            assert_eq!(g.on_pair_request(d, S(i * 11)), PairRequestVerdict::Allow);
            g.on_code_issued(d, S(i * 11));
        }
        assert_eq!(g.on_pair_request(d, S(55)), PairRequestVerdict::Refuse(S(600)));
        assert_eq!(g.refused_for(&d, S(100)), Some(S(555)));
        assert_eq!(g.on_pair_request(d, S(100)), PairRequestVerdict::Refuse(S(555)));
        assert_eq!(g.refused_for(&d, S(655)), None);
        assert_eq!(g.on_pair_request(d, S(655)), PairRequestVerdict::Allow);
    }

    #[test]
    fn window_slides() {
        let mut g = PairingGuard::new();
        let d = Uuid::new_v4();
        for i in 0..5 {
            g.on_pair_request(d, S(i * 130));
        }
        // the first request (t=0) left the 10-minute window at t=600
        assert_eq!(g.on_pair_request(d, S(650)), PairRequestVerdict::Allow);
    }

    #[test]
    fn global_lockout_escalates_and_resets_on_success() {
        let mut g = PairingGuard::new();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        g.on_code_invalidated(S(0));
        assert_eq!(g.on_pair_request(a, S(29)), PairRequestVerdict::RateLimited);
        assert_eq!(g.on_pair_request(b, S(29)), PairRequestVerdict::RateLimited);
        assert_eq!(g.on_pair_request(b, S(30)), PairRequestVerdict::Allow);
        g.on_code_invalidated(S(40));
        assert_eq!(g.locked_for(S(40)), Some(S(60)));
        g.on_paired();
        assert_eq!(g.locked_for(S(41)), None);
        g.on_code_invalidated(S(50));
        assert_eq!(g.locked_for(S(50)), Some(S(30)), "escalation reset");
    }

    #[test]
    fn tracked_devices_are_bounded_and_pruned() {
        let mut g = PairingGuard::new();
        for i in 0..(MAX_TRACKED_DEVICES as u64 + 10) {
            g.on_pair_request(Uuid::new_v4(), S(i));
        }
        assert!(g.tracked_devices() <= MAX_TRACKED_DEVICES);
        g.prune(S(10_000));
        assert_eq!(g.tracked_devices(), 0);
    }
}
