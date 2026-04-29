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
}
