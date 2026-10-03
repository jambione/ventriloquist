//! Injectable clock, so pairing-code expiry, keepalives and idle drops can be
//! tested without sleeping.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::{DateTime, FixedOffset, Local};

/// Source of time for the core.
pub trait Clock: Send + Sync + 'static {
    /// Monotonic time since an arbitrary, fixed origin. Used for every timer
    /// (code expiry, keepalive, idle drop).
    fn mono(&self) -> Duration;
    /// The current local wall-clock time. Used for the log file date, the
    /// log line time and entry timestamps.
    fn local_now(&self) -> DateTime<FixedOffset>;
}

/// The real clock: [`Instant`] for monotonic time, [`Local`] for wall time.
#[derive(Debug)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    /// A clock whose monotonic origin is now.
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn mono(&self) -> Duration {
        self.origin.elapsed()
    }
    fn local_now(&self) -> DateTime<FixedOffset> {
        Local::now().fixed_offset()
    }
}

/// A clock that only moves when told to (tests).
#[derive(Debug)]
pub struct ManualClock {
    inner: Mutex<(Duration, DateTime<FixedOffset>)>,
}

impl ManualClock {
    /// Monotonic time 0, wall time `start`.
    pub fn new(start: DateTime<FixedOffset>) -> Self {
        Self {
            inner: Mutex::new((Duration::ZERO, start)),
        }
    }

    /// Advance both monotonic and wall time by `d`.
    pub fn advance(&self, d: Duration) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.0 += d;
        g.1 += chrono::Duration::from_std(d).unwrap_or(chrono::Duration::zero());
    }

    /// Set the wall time without touching monotonic time.
    pub fn set_local(&self, t: DateTime<FixedOffset>) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.1 = t;
    }
}

impl Clock for ManualClock {
    fn mono(&self) -> Duration {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).0
    }
    fn local_now(&self) -> DateTime<FixedOffset> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_advances_both() {
        let start = DateTime::parse_from_rfc3339("2026-10-03T23:59:59+02:00").unwrap();
        let c = ManualClock::new(start);
        c.advance(Duration::from_secs(2));
        assert_eq!(c.mono(), Duration::from_secs(2));
        assert_eq!(
            c.local_now(),
            DateTime::parse_from_rfc3339("2026-10-04T00:00:01+02:00").unwrap()
        );
    }
}
