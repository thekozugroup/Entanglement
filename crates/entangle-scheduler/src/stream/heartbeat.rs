//! Heartbeat: `Ping` every interval, `PeerLost` after three missed `Pong`s
//! (spec §7.1, ATC-STR-2).
//!
//! Both ends of a stream run one of these. It is a pure state machine over
//! explicit `now` values, so the 5 s / 15 s timing is testable without
//! waiting.
//!
//! # Timing
//!
//! The first `Ping` goes out when the heartbeat starts (`t0`), then one every
//! `interval`. At each tick, a previous ping that is still unanswered counts
//! as one miss; the third consecutive miss closes the stream instead of
//! sending another ping. So with pongs dropped from `t0` on:
//!
//! ```text
//! t0        ping 0
//! t0 + 5s   ping 0 missed (1)  ping 1
//! t0 + 10s  ping 1 missed (2)  ping 2
//! t0 + 15s  ping 2 missed (3)  -> PeerLost
//! ```
//!
//! — the channel closes exactly three intervals after the first unanswered
//! ping. Any pong for an outstanding ping (late ones included: a late pong
//! still proves the peer is alive) resets the count. Pings are control
//! frames: they need no credit and flow while data credit is zero.

use std::time::{Duration, Instant};

/// Consecutive missed pongs that close a stream with `PeerLost`.
pub const MISSED_PONGS_LIMIT: u32 = 3;

/// What a heartbeat tick asks the stream to do.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Beat {
    /// Send `Ping { seq, ts_ms }`.
    Ping {
        /// Probe sequence number.
        seq: u64,
        /// Milliseconds since the heartbeat started.
        ts_ms: u64,
    },
    /// Three consecutive pongs are missing: close with `PeerLost`.
    PeerLost {
        /// Consecutive misses.
        missed: u32,
    },
}

/// One end's heartbeat state.
#[derive(Clone, Debug)]
pub struct Heartbeat {
    interval: Duration,
    started: Instant,
    next_at: Instant,
    next_seq: u64,
    /// Lowest ping sequence number not yet answered (`== next_seq` when
    /// every sent ping has been answered).
    unanswered_from: u64,
    missed: u32,
    last_rtt: Option<Duration>,
    sent_at: Option<(u64, Instant)>,
}

impl Heartbeat {
    /// A heartbeat whose first ping is due at `now`.
    pub fn new(interval: Duration, now: Instant) -> Self {
        Self {
            interval: interval.max(Duration::from_millis(1)),
            started: now,
            next_at: now,
            next_seq: 0,
            unanswered_from: 0,
            missed: 0,
            last_rtt: None,
            sent_at: None,
        }
    }

    /// When [`Heartbeat::on_tick`] next needs to run.
    pub const fn deadline(&self) -> Instant {
        self.next_at
    }

    /// The interval between pings.
    pub const fn interval(&self) -> Duration {
        self.interval
    }

    /// Consecutive misses so far.
    pub const fn missed(&self) -> u32 {
        self.missed
    }

    /// Round-trip time of the last answered ping, if any.
    pub const fn last_rtt(&self) -> Option<Duration> {
        self.last_rtt
    }

    /// Run the tick due at or before `now`. `None` if nothing is due yet.
    ///
    /// One call handles one tick; a caller that was late by several intervals
    /// is charged one miss, not several (a suspended laptop must not wake up
    /// to a spurious `PeerLost`), and the schedule restarts from `now`.
    pub fn on_tick(&mut self, now: Instant) -> Option<Beat> {
        if now < self.next_at {
            return None;
        }
        if self.unanswered_from < self.next_seq {
            self.missed += 1;
            if self.missed >= MISSED_PONGS_LIMIT {
                return Some(Beat::PeerLost {
                    missed: self.missed,
                });
            }
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.sent_at = Some((seq, now));
        self.next_at += self.interval;
        if self.next_at <= now {
            self.next_at = now + self.interval;
        }
        let ts_ms = u64::try_from(now.saturating_duration_since(self.started).as_millis())
            .unwrap_or(u64::MAX);
        Some(Beat::Ping { seq, ts_ms })
    }

    /// Record a `Pong { seq }`. Returns `false` (and changes nothing) for a
    /// pong that answers no ping this end sent — a duplicate, or a forgery.
    pub fn on_pong(&mut self, seq: u64, now: Instant) -> bool {
        if seq < self.unanswered_from || seq >= self.next_seq {
            return false;
        }
        self.unanswered_from = seq + 1;
        self.missed = 0;
        if let Some((sent_seq, at)) = self.sent_at {
            if sent_seq == seq {
                self.last_rtt = Some(now.saturating_duration_since(at));
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: Duration = Duration::from_secs(5);

    fn drive_until_lost(hb: &mut Heartbeat, t0: Instant) -> Instant {
        let mut now = t0;
        loop {
            match hb.on_tick(now) {
                Some(Beat::PeerLost { missed }) => {
                    assert_eq!(missed, MISSED_PONGS_LIMIT);
                    return now;
                }
                Some(Beat::Ping { .. }) | None => now = hb.deadline(),
            }
        }
    }

    #[test]
    fn first_ping_is_immediate_and_then_every_interval() {
        let t0 = Instant::now();
        let mut hb = Heartbeat::new(H, t0);
        assert_eq!(hb.on_tick(t0), Some(Beat::Ping { seq: 0, ts_ms: 0 }));
        assert_eq!(hb.on_tick(t0 + Duration::from_secs(4)), None);
        assert!(hb.on_pong(0, t0 + Duration::from_millis(20)));
        assert_eq!(hb.last_rtt(), Some(Duration::from_millis(20)));
        assert_eq!(
            hb.on_tick(t0 + H),
            Some(Beat::Ping {
                seq: 1,
                ts_ms: 5_000
            })
        );
        assert_eq!(hb.missed(), 0);
    }

    #[test]
    fn three_missed_pongs_from_the_start_close_at_three_intervals() {
        let t0 = Instant::now();
        let mut hb = Heartbeat::new(H, t0);
        let lost = drive_until_lost(&mut hb, t0);
        assert_eq!(lost - t0, Duration::from_secs(15));
    }

    #[test]
    fn a_pong_resets_the_count() {
        let t0 = Instant::now();
        let mut hb = Heartbeat::new(H, t0);
        hb.on_tick(t0); // ping 0
        hb.on_tick(t0 + H); // miss 1, ping 1
        hb.on_tick(t0 + 2 * H); // miss 2, ping 2
        assert_eq!(hb.missed(), 2);
        // A late pong for ping 1 still proves liveness.
        assert!(hb.on_pong(1, t0 + 2 * H + Duration::from_millis(1)));
        assert_eq!(hb.missed(), 0);
        // ping 2 is still unanswered: one miss at the next tick, not three.
        assert!(matches!(
            hb.on_tick(t0 + 3 * H),
            Some(Beat::Ping { seq: 3, .. })
        ));
        assert_eq!(hb.missed(), 1);
    }

    #[test]
    fn unknown_and_duplicate_pongs_are_ignored() {
        let t0 = Instant::now();
        let mut hb = Heartbeat::new(H, t0);
        assert!(!hb.on_pong(0, t0), "no ping sent yet");
        hb.on_tick(t0);
        assert!(!hb.on_pong(7, t0), "never sent");
        assert!(hb.on_pong(0, t0));
        assert!(!hb.on_pong(0, t0), "duplicate");
    }

    #[test]
    fn a_late_caller_is_charged_one_miss_per_tick() {
        let t0 = Instant::now();
        let mut hb = Heartbeat::new(H, t0);
        hb.on_tick(t0);
        // Woken an hour later: one miss, and the schedule restarts.
        let late = t0 + Duration::from_secs(3600);
        assert!(matches!(hb.on_tick(late), Some(Beat::Ping { .. })));
        assert_eq!(hb.missed(), 1);
        assert_eq!(hb.deadline(), late + H);
    }
}
