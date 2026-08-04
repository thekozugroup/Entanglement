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
    policy::{BrokerPolicy, CrossNodePolicy},
};
use entangle_biscuits::verifier;
use entangle_manifest::ValidatedManifest;
use entangle_types::{capability::CapabilityKind, peer_id::PeerId, plugin_id::PluginId};
use parking_lot::{Mutex, RwLock};
use std::borrow::Cow;
use std::collections::hash_map::Entry;
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
    /// Immutable for the lifetime of the registration — the deny-by-default
    /// check reads it under a *shared* lock.
    manifest: ValidatedManifest,
    /// Outstanding grants, keyed by id.
    ///
    /// Guarded by its own mutex rather than by the `plugins` lock so that
    /// issuing a grant does not need exclusive access to the whole registry
    /// (see [`Broker::grant`]). Only the [`CapabilityKind`] is stored: the
    /// holder is already the key of the enclosing `plugins` map, so keeping a
    /// whole [`GrantedCapability`] here would clone the [`PluginId`] (two
    /// `String`s) per grant for no added information;
    /// [`Broker::snapshot_grants`] reassembles the public struct on demand.
    grants: Mutex<HashMap<GrantId, CapabilityKind>>,
}

// ── Broker ──────────────────────────────────────────────────────────────────

/// Capability broker — the only component that decides what a plugin can do.
///
/// All public methods are synchronous; internally they use `parking_lot`
/// locks. The broker is designed to be wrapped in an `Arc` and shared across
/// threads.
///
/// # Locking
/// Two levels, deliberately:
/// - `plugins` (an `RwLock`) guards the *registry* — which plugins exist.
///   Only [`Broker::register_plugin`] and [`Broker::unregister_plugin`] take
///   it exclusively; [`Broker::grant`] and [`Broker::release`] take it shared,
///   so grants for different plugins (and for the same plugin) never block one
///   another on the registry.
/// - Each plugin's record then guards its own grant table with a `Mutex`,
///   held only for the map insert/remove itself.
///
/// The deny-by-default check reads the registered manifest, which is immutable
/// for the lifetime of the registration, so performing it under the shared
/// lock is exactly as authoritative as performing it under an exclusive one:
/// a plugin cannot be unregistered or re-registered while any grant holds the
/// read lock, and no other operation can change what the manifest declares.
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
    ///
    /// Registration is strictly insert-only: a second registration under the
    /// same [`PluginId`] returns [`BrokerError::AlreadyRegistered`] instead of
    /// overwriting the live record (which would silently drop its outstanding
    /// grants with no `CapabilityReleased` audit trail).
    pub fn register_plugin(&self, manifest: ValidatedManifest) -> Result<(), BrokerError> {
        self.policy.check_plugin_load(manifest.effective_tier)?;

        let plugin_id = manifest.plugin_id.clone();
        let declared_tier = manifest.declared_tier;
        let implied_tier = manifest.implied_tier;
        let effective_tier = manifest.effective_tier;

        match self.plugins.write().entry(plugin_id.clone()) {
            Entry::Occupied(_) => {
                return Err(BrokerError::AlreadyRegistered(plugin_id));
            }
            Entry::Vacant(slot) => {
                slot.insert(PluginRecord {
                    manifest,
                    grants: Mutex::new(HashMap::new()),
                });
            }
        }

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

        // Release any outstanding grants. The record is ours now (it is out of
        // the registry and nobody else holds a reference), so the grant table
        // can be taken by value.
        for (gid, kind) in removed.grants.into_inner() {
            self.audit.record(AuditEvent::CapabilityReleased {
                plugin: plugin.clone(),
                capability: format_cap(&kind),
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
        // The decision — and *only* the decision — happens under the registry
        // lock. Rendering the capability name, building the audit event and
        // appending it to the audit log all happen afterwards, so no broker
        // lock is ever held across the audit mutex or the `tracing` emit. The
        // event timestamp is still taken inside the critical section, so
        // `AuditEvent::at` continues to order decisions the way the locks
        // serialised them even if two threads append to the log out of order.
        let (granted, at) = {
            let plugins = self.plugins.read();
            let record = plugins
                .get(plugin)
                .ok_or_else(|| BrokerError::PluginNotRegistered(plugin.clone()))?;

            // Deny-by-default: requested kind must be present in manifest capabilities.
            let declared = record.manifest.capabilities.iter().any(|c| c == requested);
            if !declared {
                (None, SystemTime::now())
            } else {
                let gid = self.next_grant_id.fetch_add(1, Ordering::Relaxed);
                let mut grants = record.grants.lock();
                grants.insert(gid, requested.clone());
                let at = SystemTime::now();
                drop(grants);
                (Some(gid), at)
            }
        };

        let capability = format_cap(requested);
        match granted {
            None => {
                self.audit.record(AuditEvent::CapabilityDenied {
                    plugin: plugin.clone(),
                    capability: capability.clone(),
                    reason: Cow::Borrowed("not declared in manifest"),
                    at,
                });
                Err(BrokerError::CapabilityNotDeclared {
                    plugin: plugin.clone(),
                    capability: capability.into_owned(),
                })
            }
            Some(gid) => {
                self.audit.record(AuditEvent::CapabilityGranted {
                    plugin: plugin.clone(),
                    capability,
                    grant_id: gid,
                    at,
                });
                Ok(GrantedCapability {
                    grant_id: gid,
                    plugin: plugin.clone(),
                    kind: requested.clone(),
                })
            }
        }
    }

    /// Release a specific capability grant.
    ///
    /// Silently succeeds if the grant ID is not found (idempotent release).
    pub fn release(&self, plugin: &PluginId, grant_id: GrantId) -> Result<(), BrokerError> {
        // As in `grant`: mutate under the locks, audit after releasing them.
        let removed = {
            let plugins = self.plugins.read();
            let record = plugins
                .get(plugin)
                .ok_or_else(|| BrokerError::PluginNotRegistered(plugin.clone()))?;
            let mut grants = record.grants.lock();
            grants.remove(&grant_id).map(|k| (k, SystemTime::now()))
        };

        if let Some((kind, at)) = removed {
            self.audit.record(AuditEvent::CapabilityReleased {
                plugin: plugin.clone(),
                capability: format_cap(&kind),
                grant_id,
                at,
            });
        }

        Ok(())
    }

    /// Grant a capability AFTER verifying a presented biscuit cap.
    ///
    /// Used for cross-node grants where the caller presents a biscuit token
    /// signed by a trusted issuer. Local in-process grants still use
    /// [`Broker::grant`].
    ///
    /// The method enforces **two** independent deny-by-default layers:
    /// 1. The biscuit must be signed by a key in `cross_node_policy.trust_roots`,
    ///    not expired, bound to `local_peer_id`, and must contain the required
    ///    capability surface.
    /// 2. The plugin's manifest must also declare the requested capability
    ///    (biscuit grants are **not** a manifest bypass).
    pub fn grant_with_biscuit(
        &self,
        plugin: &PluginId,
        requested: &CapabilityKind,
        biscuit_bytes: &[u8],
        local_peer_id: PeerId,
        cross_node_policy: &CrossNodePolicy,
    ) -> Result<GrantedCapability, BrokerError> {
        // 1. Try every trust root until one accepts the biscuit.
        let mut last_err: Option<String> = None;
        let biscuit = cross_node_policy
            .trust_roots
            .iter()
            .find_map(|root| match verifier::parse(biscuit_bytes, root) {
                Ok(b) => Some(b),
                Err(e) => {
                    last_err = Some(e.to_string());
                    None
                }
            })
            .ok_or_else(|| {
                BrokerError::BiscuitVerify(
                    last_err.unwrap_or_else(|| "no trust root accepts this biscuit".into()),
                )
            })?;

        // 2. Verify claims: expiry, peer binding, required capability surface.
        let cap_str = format_cap(requested);
        verifier::verify(
            &biscuit,
            &verifier::VerifyContext {
                now_unix_secs: now_secs() as i64,
                local_peer_id,
            },
            &cap_str,
        )
        .map_err(|e| BrokerError::BiscuitVerify(e.to_string()))?;

        // 3. Biscuit is valid — ALSO enforce manifest deny-by-default.
        //    A biscuit grants are never a bypass for the manifest layer.
        self.grant(plugin, requested)
    }

    /// Return all outstanding grants for a plugin.
    pub fn snapshot_grants(&self, plugin: &PluginId) -> Vec<GrantedCapability> {
        self.plugins
            .read()
            .get(plugin)
            .map(|r| {
                r.grants
                    .lock()
                    .iter()
                    .map(|(grant_id, kind)| GrantedCapability {
                        grant_id: *grant_id,
                        plugin: plugin.clone(),
                        kind: kind.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Render a capability as its canonical audit-log name.
///
/// Returns a [`Cow`] because the overwhelmingly common capabilities are the
/// fieldless variants, whose names are compile-time constants — a grant of
/// `compute.cpu` should not have to heap-allocate its own name. Only the
/// parameterised variants actually build a string.
fn format_cap(c: &CapabilityKind) -> Cow<'static, str> {
    use CapabilityKind::*;
    match c {
        ComputeCpu => Cow::Borrowed("compute.cpu"),
        ComputeGpu => Cow::Borrowed("compute.gpu"),
        ComputeNpu => Cow::Borrowed("compute.npu"),
        StorageLocal { scope } => Cow::Owned(format!("storage.local[{scope:?}]")),
        StorageShare { name, mode } => Cow::Owned(format!("storage.share.{name}[{mode:?}]")),
        NetLan => Cow::Borrowed("net.lan"),
        NetWan => Cow::Borrowed("net.wan"),
        MeshPeer => Cow::Borrowed("mesh.peer"),
        AgentInvoke => Cow::Borrowed("agent.invoke"),
        HostDockerSocket => Cow::Borrowed("host.docker-socket"),
        Custom(s) => Cow::Owned(format!("custom.{s}")),
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

    // Test 6b — duplicate registration is refused and leaves existing state intact.
    #[test]
    fn duplicate_registration_refused_and_grants_preserved() {
        let broker = Broker::new(BrokerPolicy::default());
        let manifest = make_manifest("dup-plugin", 2, Runtime::Wasm, &["compute.cpu"]);
        let plugin_id = manifest.plugin_id.clone();
        broker.register_plugin(manifest).unwrap();

        let gc = broker
            .grant(&plugin_id, &CapabilityKind::ComputeCpu)
            .unwrap();

        let audit_len_before = broker.audit_log().len();

        // Second registration of the same id must fail without overwriting.
        let manifest2 = make_manifest("dup-plugin", 2, Runtime::Wasm, &["compute.cpu"]);
        let err = broker.register_plugin(manifest2).unwrap_err();
        assert!(
            matches!(err, BrokerError::AlreadyRegistered(ref id) if *id == plugin_id),
            "expected AlreadyRegistered, got: {err}"
        );
        assert!(
            err.to_string().contains("ENTANGLE-E0123"),
            "AlreadyRegistered must carry its error code: {err}"
        );

        // The original registration's grants survive.
        let grants = broker.snapshot_grants(&plugin_id);
        assert_eq!(grants.len(), 1, "existing grant must be preserved");
        assert_eq!(grants[0].grant_id, gc.grant_id);

        // No audit events were emitted by the failed registration.
        assert_eq!(
            broker.audit_log().len(),
            audit_len_before,
            "failed duplicate registration must not add audit events"
        );
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
