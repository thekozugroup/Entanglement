//! Audit log — every broker decision is recorded here.
//!
//! All grant, deny, register, and release events are appended to an in-memory
//! log and emitted to `tracing` at `INFO` level under the `entangle::audit`
//! target. Callers may snapshot the log for inspection or export.
//!
//! The in-memory buffer is bounded (see [`AuditLog::with_capacity`]): once
//! `max_events` is reached the oldest events are evicted and counted in
//! [`AuditLog::dropped`], so a long-running daemon cannot grow without limit.
//! Every event is still emitted to `tracing` before any eviction, so a
//! persistent subscriber keeps the full history.

use entangle_types::{plugin_id::PluginId, tier::Tier};
use std::borrow::Cow;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

/// A single auditable decision made by the broker.
#[derive(Clone, Debug)]
pub enum AuditEvent {
    /// A plugin was successfully registered with the broker.
    PluginRegistered {
        /// The registered plugin.
        plugin: PluginId,
        /// Tier explicitly declared in the plugin manifest.
        declared_tier: Tier,
        /// Tier implied by the plugin's capability set.
        implied_tier: Tier,
        /// Effective runtime ceiling (`max(declared, implied)`).
        effective_tier: Tier,
        /// Wall-clock time of registration.
        at: SystemTime,
    },
    /// A plugin was removed from the broker.
    PluginUnregistered {
        /// The removed plugin.
        plugin: PluginId,
        /// Wall-clock time of removal.
        at: SystemTime,
    },
    /// A capability grant was issued to a plugin.
    CapabilityGranted {
        /// The plugin that received the grant.
        plugin: PluginId,
        /// Human-readable capability name (e.g. `"compute.cpu"`).
        ///
        /// A [`Cow`] so the fieldless capability kinds — which are the ones a
        /// busy daemon grants over and over — can carry their `&'static str`
        /// name without a per-event allocation.
        capability: Cow<'static, str>,
        /// Monotonic grant identifier.
        grant_id: u64,
        /// Wall-clock time of the grant.
        at: SystemTime,
    },
    /// A capability request was denied.
    CapabilityDenied {
        /// The plugin whose request was denied.
        plugin: PluginId,
        /// Human-readable capability name.
        capability: Cow<'static, str>,
        /// Human-readable denial reason.
        reason: Cow<'static, str>,
        /// Wall-clock time of the denial.
        at: SystemTime,
    },
    /// An outstanding capability grant was released.
    CapabilityReleased {
        /// The plugin whose grant was released.
        plugin: PluginId,
        /// Human-readable capability name.
        capability: Cow<'static, str>,
        /// The grant identifier that was released.
        grant_id: u64,
        /// Wall-clock time of the release.
        at: SystemTime,
    },
}

/// Discriminator for filtering [`AuditEvent`]s.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AuditKind {
    /// Matches [`AuditEvent::PluginRegistered`].
    PluginRegistered,
    /// Matches [`AuditEvent::PluginUnregistered`].
    PluginUnregistered,
    /// Matches [`AuditEvent::CapabilityGranted`].
    CapabilityGranted,
    /// Matches [`AuditEvent::CapabilityDenied`].
    CapabilityDenied,
    /// Matches [`AuditEvent::CapabilityReleased`].
    CapabilityReleased,
}

impl AuditEvent {
    /// Discriminator for this event variant.
    pub fn kind(&self) -> AuditKind {
        match self {
            AuditEvent::PluginRegistered { .. } => AuditKind::PluginRegistered,
            AuditEvent::PluginUnregistered { .. } => AuditKind::PluginUnregistered,
            AuditEvent::CapabilityGranted { .. } => AuditKind::CapabilityGranted,
            AuditEvent::CapabilityDenied { .. } => AuditKind::CapabilityDenied,
            AuditEvent::CapabilityReleased { .. } => AuditKind::CapabilityReleased,
        }
    }

    /// Wall-clock timestamp recorded with this event.
    pub fn at(&self) -> SystemTime {
        match *self {
            AuditEvent::PluginRegistered { at, .. } => at,
            AuditEvent::PluginUnregistered { at, .. } => at,
            AuditEvent::CapabilityGranted { at, .. } => at,
            AuditEvent::CapabilityDenied { at, .. } => at,
            AuditEvent::CapabilityReleased { at, .. } => at,
        }
    }
}

/// Default retention cap for [`AuditLog`] — see [`AuditLog::with_capacity`].
pub const DEFAULT_MAX_EVENTS: usize = 10_000;

/// Thread-safe, bounded, append-only log of [`AuditEvent`]s.
///
/// Retains at most `max_events` events in memory; older events are evicted
/// FIFO and counted in [`AuditLog::dropped`].
pub struct AuditLog {
    events: parking_lot::Mutex<VecDeque<AuditEvent>>,
    max_events: usize,
    dropped: AtomicU64,
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_MAX_EVENTS)
    }
}

impl AuditLog {
    /// Construct a log retaining at most `max_events` events in memory
    /// (values below 1 are clamped to 1).
    pub fn with_capacity(max_events: usize) -> Self {
        Self {
            events: parking_lot::Mutex::new(VecDeque::new()),
            max_events: max_events.max(1),
            dropped: AtomicU64::new(0),
        }
    }

    /// The maximum number of events retained in memory.
    pub fn max_events(&self) -> usize {
        self.max_events
    }

    /// Number of events evicted so far to stay within [`AuditLog::max_events`].
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Append an event to the log and emit it via `tracing`.
    ///
    /// When the log is at capacity the oldest retained event is evicted and
    /// the dropped counter incremented.
    pub fn record(&self, e: AuditEvent) {
        tracing::info!(target: "entangle::audit", event = ?e, "broker audit");
        let mut events = self.events.lock();
        while events.len() >= self.max_events {
            events.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        events.push_back(e);
    }

    /// Return a point-in-time snapshot of all currently retained events
    /// (oldest first).
    pub fn snapshot(&self) -> Vec<AuditEvent> {
        self.events.lock().iter().cloned().collect()
    }

    /// Return the number of events currently retained (excludes dropped ones).
    pub fn len(&self) -> usize {
        self.events.lock().len()
    }

    /// Returns `true` when no events are currently retained.
    pub fn is_empty(&self) -> bool {
        self.events.lock().is_empty()
    }

    /// Filtered snapshot: retained events with `at >= since` and matching
    /// `kind` (if `kind` is `Some`). Mainly intended for the operator-facing
    /// `entangle perms log` command (Phase 2 CLI).
    pub fn filter(&self, since: SystemTime, kind: Option<AuditKind>) -> Vec<AuditEvent> {
        self.events
            .lock()
            .iter()
            .filter(|e| e.at() >= since && kind.map(|k| e.kind() == k).unwrap_or(true))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use entangle_types::plugin_id::PluginId;

    fn plugin(name: &str) -> PluginId {
        PluginId::new("a".repeat(32), name, "0.1.0".parse().unwrap()).unwrap()
    }

    #[test]
    fn kind_discriminator_round_trips_every_variant() {
        let now = SystemTime::now();
        let cases = [
            (
                AuditEvent::PluginRegistered {
                    plugin: plugin("a"),
                    declared_tier: Tier::Pure,
                    implied_tier: Tier::Pure,
                    effective_tier: Tier::Pure,
                    at: now,
                },
                AuditKind::PluginRegistered,
            ),
            (
                AuditEvent::PluginUnregistered {
                    plugin: plugin("b"),
                    at: now,
                },
                AuditKind::PluginUnregistered,
            ),
            (
                AuditEvent::CapabilityGranted {
                    plugin: plugin("c"),
                    capability: "compute.cpu".into(),
                    grant_id: 1,
                    at: now,
                },
                AuditKind::CapabilityGranted,
            ),
            (
                AuditEvent::CapabilityDenied {
                    plugin: plugin("d"),
                    capability: "host.docker-socket".into(),
                    reason: "x".into(),
                    at: now,
                },
                AuditKind::CapabilityDenied,
            ),
            (
                AuditEvent::CapabilityReleased {
                    plugin: plugin("e"),
                    capability: "compute.cpu".into(),
                    grant_id: 1,
                    at: now,
                },
                AuditKind::CapabilityReleased,
            ),
        ];
        for (e, k) in cases {
            assert_eq!(e.kind(), k);
            assert_eq!(e.at(), now);
        }
    }

    #[test]
    fn filter_since_drops_older_events() {
        let log = AuditLog::default();
        let earlier = SystemTime::UNIX_EPOCH;
        let later = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(86_400);
        log.record(AuditEvent::PluginRegistered {
            plugin: plugin("old"),
            declared_tier: Tier::Pure,
            implied_tier: Tier::Pure,
            effective_tier: Tier::Pure,
            at: earlier,
        });
        log.record(AuditEvent::PluginRegistered {
            plugin: plugin("new"),
            declared_tier: Tier::Pure,
            implied_tier: Tier::Pure,
            effective_tier: Tier::Pure,
            at: later,
        });
        let kept = log.filter(later, None);
        assert_eq!(kept.len(), 1, "filter must drop the earlier event");
        assert_eq!(kept[0].at(), later);
    }

    #[test]
    fn filter_by_kind_only_returns_matching_variants() {
        let log = AuditLog::default();
        let t = SystemTime::UNIX_EPOCH;
        log.record(AuditEvent::CapabilityGranted {
            plugin: plugin("x"),
            capability: "compute.cpu".into(),
            grant_id: 1,
            at: t,
        });
        log.record(AuditEvent::CapabilityDenied {
            plugin: plugin("x"),
            capability: "host.docker-socket".into(),
            reason: "not declared".into(),
            at: t,
        });
        let denied = log.filter(t, Some(AuditKind::CapabilityDenied));
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].kind(), AuditKind::CapabilityDenied);
    }

    fn registered(name: &str, at: SystemTime) -> AuditEvent {
        AuditEvent::PluginRegistered {
            plugin: plugin(name),
            declared_tier: Tier::Pure,
            implied_tier: Tier::Pure,
            effective_tier: Tier::Pure,
            at,
        }
    }

    #[test]
    fn record_caps_at_max_events_and_counts_dropped() {
        let log = AuditLog::with_capacity(3);
        assert_eq!(log.max_events(), 3);

        let t = SystemTime::UNIX_EPOCH;
        for name in ["a", "b", "c", "d", "e"] {
            log.record(registered(name, t));
        }

        assert_eq!(log.len(), 3, "log must retain at most max_events");
        assert_eq!(
            log.dropped(),
            2,
            "two oldest events must be counted dropped"
        );

        // The snapshot keeps the newest events, oldest first.
        let names: Vec<String> = log
            .snapshot()
            .iter()
            .map(|e| match e {
                AuditEvent::PluginRegistered { plugin, .. } => plugin.name.clone(),
                _ => unreachable!("only PluginRegistered recorded"),
            })
            .collect();
        assert_eq!(names, ["c", "d", "e"]);
    }

    #[test]
    fn default_log_uses_default_cap_and_drops_nothing_when_under_it() {
        let log = AuditLog::default();
        assert_eq!(log.max_events(), DEFAULT_MAX_EVENTS);
        log.record(registered("x", SystemTime::UNIX_EPOCH));
        assert_eq!(log.len(), 1);
        assert_eq!(log.dropped(), 0);
        assert!(!log.is_empty());
    }

    #[test]
    fn zero_capacity_is_clamped_to_one() {
        let log = AuditLog::with_capacity(0);
        assert_eq!(log.max_events(), 1);
        let t = SystemTime::UNIX_EPOCH;
        log.record(registered("a", t));
        log.record(registered("b", t));
        assert_eq!(log.len(), 1);
        assert_eq!(log.dropped(), 1);
    }
}
