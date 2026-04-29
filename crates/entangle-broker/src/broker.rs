//! The capability broker — the sole authority that grants or denies capabilities.
//!
//! # Design
//! - **Deny-by-default**: a capability is only granted if it appears in the
//!   plugin's validated manifest capability list.
//! - **No ambient authority** (spec §11): a plugin cannot obtain a capability
//!   it did not explicitly declare at manifest time.
//! - **Every decision is audited** via [`AuditLog`].
//! - **Tier ceiling** (spec §9.4.1): plugins whose effective tier exceeds
//!   [`BrokerPolicy::max_tier_allowed`] are refused at registration.

use crate::{
    audit::{AuditEvent, AuditLog},
    errors::BrokerError,
    policy::BrokerPolicy,
};
use entangle_manifest::ValidatedManifest;
use entangle_types::{capability::CapabilityKind, plugin_id::PluginId};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

/// Monotonically increasing grant identifier.
pub type GrantId = u64;

/// A capability grant issued to a specific plugin.
#[derive(Clone, Debug)]
pub struct GrantedCapability {
    /// Unique identifier for this grant.
    pub grant_id: GrantId,
    /// The plugin that holds this grant.
    pub plugin: PluginId,
    /// The capability kind that was granted.
    pub kind: CapabilityKind,
}

// ── internal ────────────────────────────────────────────────────────────────

struct PluginRecord {
    manifest: ValidatedManifest,
    grants: HashMap<GrantId, GrantedCapability>,
}

// ── Broker ──────────────────────────────────────────────────────────────────

/// Capability broker — the only component that decides what a plugin can do.
///
/// All public methods are synchronous and lock-free at the hot path level
/// (they use `parking_lot` read-write locks internally). The broker is
/// designed to be wrapped in an `Arc` and shared across threads.
pub struct Broker {
    policy: BrokerPolicy,
    plugins: RwLock<HashMap<PluginId, PluginRecord>>,
    next_grant_id: AtomicU64,
    audit: Arc<AuditLog>,
}

impl Broker {
    /// Construct a broker with the given daemon-wide policy.
    pub fn new(policy: BrokerPolicy) -> Self {
        Self {
            policy,
            plugins: RwLock::new(HashMap::new()),
            next_grant_id: AtomicU64::new(1),
            audit: Arc::new(AuditLog::default()),
        }
    }

    /// Return a shared reference to the audit log.
    pub fn audit_log(&self) -> Arc<AuditLog> {
        self.audit.clone()
    }

    /// Return a reference to the daemon-wide policy.
    pub fn policy(&self) -> &BrokerPolicy {
        &self.policy
    }

    /// Register a validated plugin manifest with the broker.
    ///
    /// Enforces the tier ceiling from [`BrokerPolicy::max_tier_allowed`]
    /// (spec §9.4.1). The manifest validation layer (`entangle-manifest`)
    /// has already ensured `declared >= implied` (spec §4.4.1); the broker
    /// does not re-check that invariant.
    pub fn register_plugin(&self, manifest: ValidatedManifest) -> Result<(), BrokerError> {
        self.policy.check_plugin_load(manifest.effective_tier)?;

        let plugin_id = manifest.plugin_id.clone();
        let declared_tier = manifest.declared_tier;
        let implied_tier = manifest.implied_tier;
        let effective_tier = manifest.effective_tier;

        self.plugins.write().insert(
            plugin_id.clone(),
            PluginRecord {
                manifest,
                grants: HashMap::new(),
            },
        );

        self.audit.record(AuditEvent::PluginRegistered {
            plugin: plugin_id,
            declared_tier,
            implied_tier,
            effective_tier,
            at: SystemTime::now(),
        });

        Ok(())
    }

    /// Unregister a plugin, automatically releasing all outstanding grants.
    pub fn unregister_plugin(&self, plugin: &PluginId) -> Result<(), BrokerError> {
        let removed = self
            .plugins
            .write()
            .remove(plugin)
            .ok_or_else(|| BrokerError::PluginNotRegistered(plugin.clone()))?;

        // Release any outstanding grants.
        for (gid, gc) in removed.grants {
            self.audit.record(AuditEvent::CapabilityReleased {
                plugin: plugin.clone(),
                capability: format_cap(&gc.kind),
                grant_id: gid,
                at: SystemTime::now(),
            });
        }

        self.audit.record(AuditEvent::PluginUnregistered {
            plugin: plugin.clone(),
            at: SystemTime::now(),
        });

        Ok(())
    }

    /// Grant a capability the plugin declared at manifest time.
    ///
    /// Denies with [`BrokerError::CapabilityNotDeclared`] if the requested
    /// capability was not listed in the plugin's manifest — enforcing the
    /// no-ambient-authority invariant (spec §11).
    pub fn grant(
        &self,
        plugin: &PluginId,
        requested: &CapabilityKind,
    ) -> Result<GrantedCapability, BrokerError> {
        let mut plugins = self.plugins.write();
        let record = plugins
            .get_mut(plugin)
            .ok_or_else(|| BrokerError::PluginNotRegistered(plugin.clone()))?;

        // Deny-by-default: requested kind must be present in manifest capabilities.
        let declared = record.manifest.capabilities.iter().any(|c| c == requested);
        if !declared {
            self.audit.record(AuditEvent::CapabilityDenied {
                plugin: plugin.clone(),
                capability: format_cap(requested),
                reason: "not declared in manifest".to_string(),
                at: SystemTime::now(),
            });
            return Err(BrokerError::CapabilityNotDeclared {
                plugin: plugin.clone(),
                capability: format_cap(requested),
            });
        }

        let gid = self.next_grant_id.fetch_add(1, Ordering::Relaxed);
        let gc = GrantedCapability {
            grant_id: gid,
            plugin: plugin.clone(),
            kind: requested.clone(),
        };
        record.grants.insert(gid, gc.clone());

        self.audit.record(AuditEvent::CapabilityGranted {
            plugin: plugin.clone(),
            capability: format_cap(requested),
            grant_id: gid,
            at: SystemTime::now(),
        });

        Ok(gc)
    }

    /// Release a specific capability grant.
    ///
    /// Silently succeeds if the grant ID is not found (idempotent release).
    pub fn release(&self, plugin: &PluginId, grant_id: GrantId) -> Result<(), BrokerError> {
        let mut plugins = self.plugins.write();
        let record = plugins
            .get_mut(plugin)
            .ok_or_else(|| BrokerError::PluginNotRegistered(plugin.clone()))?;

        if let Some(gc) = record.grants.remove(&grant_id) {
            self.audit.record(AuditEvent::CapabilityReleased {
                plugin: plugin.clone(),
                capability: format_cap(&gc.kind),
                grant_id,
                at: SystemTime::now(),
            });
        }

        Ok(())
    }

    /// Return all outstanding grants for a plugin.
    pub fn snapshot_grants(&self, plugin: &PluginId) -> Vec<GrantedCapability> {
        self.plugins
            .read()
            .get(plugin)
            .map(|r| r.grants.values().cloned().collect())
            .unwrap_or_default()
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn format_cap(c: &CapabilityKind) -> String {
    use CapabilityKind::*;
    match c {
        ComputeCpu => "compute.cpu".into(),
        ComputeGpu => "compute.gpu".into(),
        ComputeNpu => "compute.npu".into(),
        StorageLocal { scope } => format!("storage.local[{scope:?}]"),
        StorageShare { name, mode } => format!("storage.share.{name}[{mode:?}]"),
        NetLan => "net.lan".into(),
        NetWan => "net.wan".into(),
        MeshPeer => "mesh.peer".into(),
        AgentInvoke => "agent.invoke".into(),
        HostDockerSocket => "host.docker-socket".into(),
        Custom(s) => format!("custom.{s}"),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::BrokerPolicy;
    use entangle_manifest::{
        schema::{BuildSection, Manifest, PluginSection, Runtime},
        validate::validate,
    };
    use entangle_types::tier::Tier;

    const PUB: &str = "aabbccddeeff00112233445566778899";

    fn make_manifest(name: &str, tier: u8, runtime: Runtime, caps: &[&str]) -> ValidatedManifest {
        let mut m = Manifest {
            plugin: PluginSection {
                id: format!("{PUB}/{name}@0.1.0"),
                version: semver::Version::parse("0.1.0").unwrap(),
                tier,
                runtime,
                description: String::new(),
            },
            capabilities: Default::default(),
            build: Some(BuildSection {
                wit_world: None,
                target: None,
            }),
            signature: None,
        };
        for cap in caps {
            m.capabilities
                .insert(cap.to_string(), toml::Value::Table(Default::default()));
        }
        validate(m).expect("test manifest must be valid")
    }

    // Test 1
    #[test]
    fn max_tier_allowed_blocks_high_tier() {
        let policy = BrokerPolicy {
            max_tier_allowed: Tier::Sandboxed,
            ..Default::default()
        };
        let broker = Broker::new(policy);
        let manifest = make_manifest("native-plugin", 5, Runtime::Native, &["host.docker-socket"]);
        let err = broker.register_plugin(manifest).unwrap_err();
        assert!(
            matches!(
                err,
                BrokerError::Policy(crate::policy::PolicyError::TierAboveCeiling { .. })
            ),
            "expected TierAboveCeiling, got: {err}"
        );
    }

    // Test 2
    #[test]
    fn policy_allows_when_within_ceiling() {
        let policy = BrokerPolicy {
            max_tier_allowed: Tier::Sandboxed,
            ..Default::default()
        };
        let broker = Broker::new(policy);
        let manifest = make_manifest("sandbox-plugin", 2, Runtime::Wasm, &["compute.cpu"]);
        assert!(broker.register_plugin(manifest).is_ok());
    }

    // Test 3
    #[test]
    fn grant_undeclared_capability_denied() {
        let broker = Broker::new(BrokerPolicy::default());
        let manifest = make_manifest("cpu-only", 2, Runtime::Wasm, &["compute.cpu"]);
        let plugin_id = manifest.plugin_id.clone();
        broker.register_plugin(manifest).unwrap();

        let err = broker
            .grant(&plugin_id, &CapabilityKind::HostDockerSocket)
            .unwrap_err();
        assert!(
            matches!(err, BrokerError::CapabilityNotDeclared { .. }),
            "expected CapabilityNotDeclared, got: {err}"
        );

        // Verify audit event recorded
        let events = broker.audit_log().snapshot();
        let denied = events.iter().any(|e| {
            matches!(
                e,
                AuditEvent::CapabilityDenied {
                    capability,
                    ..
                } if capability == "host.docker-socket"
            )
        });
        assert!(denied, "expected CapabilityDenied audit event");
    }

    // Test 4
    #[test]
    fn grant_declared_capability_succeeds() {
        let broker = Broker::new(BrokerPolicy::default());
        let manifest = make_manifest("cpu-plugin", 2, Runtime::Wasm, &["compute.cpu"]);
        let plugin_id = manifest.plugin_id.clone();
        broker.register_plugin(manifest).unwrap();

        let gc = broker
            .grant(&plugin_id, &CapabilityKind::ComputeCpu)
            .unwrap();
        assert_eq!(gc.plugin, plugin_id);
        assert_eq!(gc.kind, CapabilityKind::ComputeCpu);
        assert!(gc.grant_id >= 1, "grant_id must be monotonic");

        // Second grant gets a higher id
        let gc2 = broker
            .grant(&plugin_id, &CapabilityKind::ComputeCpu)
            .unwrap();
        assert!(
            gc2.grant_id > gc.grant_id,
            "grant_ids must be monotonically increasing"
        );

        // Verify audit event
        let events = broker.audit_log().snapshot();
        let granted = events.iter().any(|e| {
            matches!(
                e,
                AuditEvent::CapabilityGranted {
                    capability,
                    ..
                } if capability == "compute.cpu"
            )
        });
        assert!(granted, "expected CapabilityGranted audit event");
    }

    // Test 5
    #[test]
    fn release_grant_logs_audit_event() {
        let broker = Broker::new(BrokerPolicy::default());
        let manifest = make_manifest("rel-plugin", 2, Runtime::Wasm, &["compute.cpu"]);
        let plugin_id = manifest.plugin_id.clone();
        broker.register_plugin(manifest).unwrap();

        let gc = broker
            .grant(&plugin_id, &CapabilityKind::ComputeCpu)
            .unwrap();
        broker.release(&plugin_id, gc.grant_id).unwrap();

        let events = broker.audit_log().snapshot();
        let released = events.iter().any(|e| {
            matches!(
                e,
                AuditEvent::CapabilityReleased {
                    grant_id,
                    ..
                } if *grant_id == gc.grant_id
            )
        });
        assert!(released, "expected CapabilityReleased audit event");
    }

    // Test 6
    #[test]
    fn unregister_plugin_releases_outstanding_grants() {
        let broker = Broker::new(BrokerPolicy::default());
        let manifest = make_manifest("unreg-plugin", 2, Runtime::Wasm, &["compute.cpu"]);
        let plugin_id = manifest.plugin_id.clone();
        broker.register_plugin(manifest).unwrap();

        let gc = broker
            .grant(&plugin_id, &CapabilityKind::ComputeCpu)
            .unwrap();

        broker.unregister_plugin(&plugin_id).unwrap();

        let events = broker.audit_log().snapshot();

        // Both a CapabilityReleased and a PluginUnregistered must appear
        let released = events.iter().any(|e| {
            matches!(
                e,
                AuditEvent::CapabilityReleased {
                    grant_id,
                    ..
                } if *grant_id == gc.grant_id
            )
        });
        let unregistered = events.iter().any(
            |e| matches!(e, AuditEvent::PluginUnregistered { plugin, .. } if plugin == &plugin_id),
        );

        assert!(
            released,
            "expected CapabilityReleased audit event on unregister"
        );
        assert!(unregistered, "expected PluginUnregistered audit event");
    }

    // Test 7
    #[test]
    fn startup_multi_node_no_allowlist_errors() {
        let policy = BrokerPolicy {
            multi_node: true,
            peer_allowlist_populated: false,
            ..Default::default()
        };
        let err = policy.check_startup().unwrap_err();
        assert!(
            matches!(err, crate::policy::PolicyError::MultiNodeNoAllowlist),
            "expected MultiNodeNoAllowlist, got: {err}"
        );
    }

    // Test 8 — ENTANGLE-E0042 is caught by entangle-manifest::validate, not the broker.
    // The broker receives only already-validated manifests; this test confirms the
    // validation layer rejects a manifest where declared tier < implied tier.
    #[test]
    fn tier_below_capability_caught_at_validation_layer() {
        use entangle_manifest::{
            schema::{BuildSection, Manifest, PluginSection, Runtime},
            validate::validate,
            validate::ValidationError,
        };

        let mut m = Manifest {
            plugin: PluginSection {
                id: format!("{PUB}/too-low@0.1.0"),
                version: semver::Version::parse("0.1.0").unwrap(),
                tier: 2, // Sandboxed — but host.docker-socket requires Native (5)
                runtime: Runtime::Wasm,
                description: String::new(),
            },
            capabilities: Default::default(),
            build: Some(BuildSection {
                wit_world: None,
                target: None,
            }),
            signature: None,
        };
        m.capabilities.insert(
            "host.docker-socket".into(),
            toml::Value::Table(Default::default()),
        );

        let err = validate(m).expect_err("validation must reject declared < implied tier");
        assert!(
            matches!(err, ValidationError::TierBelowCapability { .. }),
            "expected ENTANGLE-E0042 TierBelowCapability from manifest layer, got: {err}"
        );
        // The broker never sees this manifest; no BrokerError::TierBelowCapability needed here.
    }
}
