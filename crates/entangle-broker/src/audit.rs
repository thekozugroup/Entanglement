//! Audit log — every broker decision is recorded here.
//!
//! All grant, deny, register, and release events are appended to an in-memory
//! log and emitted to `tracing` at `INFO` level under the `entangle::audit`
//! target. Callers may snapshot the log for inspection or export.

use entangle_types::{plugin_id::PluginId, tier::Tier};
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
        capability: String,
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
        capability: String,
        /// Human-readable denial reason.
        reason: String,
        /// Wall-clock time of the denial.
        at: SystemTime,
    },
    /// An outstanding capability grant was released.
    CapabilityReleased {
        /// The plugin whose grant was released.
        plugin: PluginId,
        /// Human-readable capability name.
        capability: String,
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

/// Thread-safe, append-only log of [`AuditEvent`]s.
#[derive(Default)]
pub struct AuditLog {
    events: parking_lot::Mutex<Vec<AuditEvent>>,
}

impl AuditLog {
    /// Append an event to the log and emit it via `tracing`.
    pub fn record(&self, e: AuditEvent) {
        tracing::info!(target: "entangle::audit", event = ?e, "broker audit");
        self.events.lock().push(e);
    }

    /// Return a point-in-time snapshot of all recorded events.
    pub fn snapshot(&self) -> Vec<AuditEvent> {
        self.events.lock().clone()
    }

    /// Return the number of events recorded so far.
    pub fn len(&self) -> usize {
        self.events.lock().len()
    }

    /// Returns `true` when no events have been recorded.
    pub fn is_empty(&self) -> bool {
        self.events.lock().is_empty()
    }

    /// Filtered snapshot: events with `at >= since` and matching `kind`
    /// (if `kind` is `Some`). Mainly intended for the operator-facing
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
}
