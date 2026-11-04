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
//! - **Operator policy** (spec §4.5): a capability matching
//!   [`BrokerPolicy::denied_capabilities`] is never granted, declared or not.
//!   For a native plugin, whose OS sandbox allows or forbids IP networking
//!   as a whole, denying either `net.lan` or `net.wan` denies both.
//! - **Revocation** (spec §4.6): [`Broker::revoke`] withdraws a capability
//!   from a plugin for the rest of its registration; later requests are
//!   refused as revoked.
//!
//! # Decision order
//! [`Broker::grant`] checks, in order: the plugin is registered; the manifest
//! declares exactly this capability (`not_declared`); the plugin's effective
//! tier is within the ceiling (`tier_ceiling`); no operator deny pattern
//! matches (`operator_policy`); the capability has not been revoked
//! (`revoked`). The first failing check is the denial reason recorded in the
//! audit log and in `entangle_capability_denials_total{reason}`.

use crate::{
    audit::{AuditEvent, AuditLog},
    errors::{BrokerError, Refusal},
    policy::{BrokerPolicy, CrossNodePolicy},
};
use entangle_biscuits::verifier;
use entangle_manifest::{Runtime, ValidatedManifest};
use entangle_types::{
    capability::CapabilityKind, peer_id::PeerId, plugin_id::PluginId, tier::Tier,
};
use parking_lot::{Mutex, RwLock};
use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::collections::{BTreeSet, HashMap};
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

/// The outcome of [`Broker::grant_declared`]: every declared capability is
/// either granted or denied, with the reason.
#[derive(Clone, Debug, Default)]
pub struct Resolution {
    /// Grants issued, in manifest order.
    pub granted: Vec<GrantedCapability>,
    /// Declared capabilities that were refused (operator policy, revocation,
    /// tier ceiling), with the refusal.
    pub denied: Vec<(CapabilityKind, String)>,
}

/// Where a declared capability stands, as shown by `entangle perms list`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrantState {
    /// Granted; these grants are outstanding.
    Granted {
        /// Outstanding grant ids (the load-time grant plus any handles the
        /// plugin holds right now).
        grant_ids: Vec<GrantId>,
    },
    /// Refused by the broker policy (tier ceiling or operator deny list).
    Denied {
        /// Human-readable reason.
        reason: String,
    },
    /// Withdrawn by [`Broker::revoke`]; refused until the plugin is reloaded.
    Revoked,
    /// Declared and grantable, but no grant is outstanding (e.g. never
    /// resolved, or released).
    NotGranted,
}

/// One declared capability and its [`GrantState`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityStatus {
    /// The declared capability, with its manifest parameters.
    pub capability: CapabilityKind,
    /// Where it stands.
    pub state: GrantState,
}

// ── internal ────────────────────────────────────────────────────────────────

struct PluginRecord {
    /// Immutable for the lifetime of the registration — the deny-by-default
    /// check reads it under a *shared* lock.
    manifest: ValidatedManifest,
    /// Outstanding grants and revocations.
    ///
    /// Guarded by its own mutex rather than by the `plugins` lock so that
    /// issuing a grant does not need exclusive access to the whole registry
    /// (see [`Broker::grant`]).
    table: Mutex<GrantTable>,
}

#[derive(Default)]
struct GrantTable {
    /// Outstanding grants, keyed by id.
    ///
    /// Only the [`CapabilityKind`] is stored: the holder is already the key
    /// of the enclosing `plugins` map, so keeping a whole
    /// [`GrantedCapability`] here would clone the [`PluginId`] (two
    /// `String`s) per grant for no added information;
    /// [`Broker::snapshot_grants`] reassembles the public struct on demand.
    grants: HashMap<GrantId, CapabilityKind>,
    /// Capability keys withdrawn by [`Broker::revoke`]. Checked and updated
    /// under the same lock as `grants`, so a grant can never be issued for a
    /// key between its revocation and the removal of its outstanding grants.
    revoked: BTreeSet<String>,
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
    /// Metrics sink; `None` until [`Broker::with_metrics`].
    metrics: Option<entangle_observability::Registry>,
}

impl Broker {
    /// Construct a broker with the given daemon-wide policy.
    pub fn new(policy: BrokerPolicy) -> Self {
        Self {
            policy,
            plugins: RwLock::new(HashMap::new()),
            next_grant_id: AtomicU64::new(1),
            audit: Arc::new(AuditLog::default()),
            metrics: None,
        }
    }

    /// Count grants, denials and biscuit verifications into `registry`.
    ///
    /// The `capability` label is the capability *kind* (`compute.cpu`,
    /// `storage.local`, `storage.share`, `custom`, ...), never a share name or
    /// custom string, so its cardinality is fixed.
    #[must_use]
    pub fn with_metrics(mut self, registry: entangle_observability::Registry) -> Self {
        self.metrics = Some(registry);
        self
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
    /// (spec §9.4.1), and re-checks the tier binding (spec §4.3): every
    /// declared capability's `min_tier` must be within the manifest's
    /// declared and effective tiers, or the registration is refused with
    /// [`BrokerError::TierBelowCapability`] (`ENTANGLE-E0042`). Validation
    /// already ensures this, but [`ValidatedManifest`]'s fields are public,
    /// so a capability list changed after validation must not pass for a
    /// validated one. The registered manifest is private to the broker and
    /// never changes, so every later grant (which must match a declared
    /// capability) is within the tier too.
    ///
    /// Registration is strictly insert-only: a second registration under the
    /// same [`PluginId`] returns [`BrokerError::AlreadyRegistered`] instead of
    /// overwriting the live record (which would silently drop its outstanding
    /// grants with no `CapabilityReleased` audit trail).
    pub fn register_plugin(&self, manifest: ValidatedManifest) -> Result<(), BrokerError> {
        self.policy.check_plugin_load(manifest.effective_tier)?;
        let ceiling = manifest.declared_tier.min(manifest.effective_tier);
        if let Some(cap) = manifest
            .capabilities
            .iter()
            .find(|c| c.min_tier() > ceiling)
        {
            return Err(BrokerError::TierBelowCapability {
                plugin: manifest.plugin_id.clone(),
                declared: ceiling,
                implied: cap.min_tier(),
                capability: cap.key().into_owned(),
            });
        }

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
                    table: Mutex::new(GrantTable::default()),
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
        for (gid, kind) in removed.table.into_inner().grants {
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
    /// capability (with exactly these parameters) was not listed in the
    /// plugin's manifest — enforcing the no-ambient-authority invariant (spec
    /// §11) — then applies the tier ceiling, the operator deny list
    /// ([`BrokerError::CapabilityDeniedByPolicy`]) and revocation
    /// ([`BrokerError::CapabilityRevoked`]); see the module docs for the
    /// order. Every decision is audited and counted.
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
        let (decision, at) = {
            let plugins = self.plugins.read();
            let record = plugins
                .get(plugin)
                .ok_or_else(|| BrokerError::PluginNotRegistered(plugin.clone()))?;
            let decision = self.decide(record, requested);
            (decision, SystemTime::now())
        };
        self.record_decision(plugin, requested, decision, at)
    }

    /// Grant the declared capability whose manifest key (see
    /// [`CapabilityKind::key`]) is `key` — `net.wan`, `storage.local`,
    /// `storage.share.photos`, `custom.x`.
    ///
    /// This is how a plugin's runtime `capability.fetch(kind, name)` reaches
    /// the broker: the plugin names a capability, the manifest supplies its
    /// parameters. A key the manifest does not declare is denied (and
    /// audited) as [`BrokerError::CapabilityNotDeclared`].
    pub fn grant_by_key(
        &self,
        plugin: &PluginId,
        key: &str,
    ) -> Result<GrantedCapability, BrokerError> {
        let (declared, at) = {
            let plugins = self.plugins.read();
            let record = plugins
                .get(plugin)
                .ok_or_else(|| BrokerError::PluginNotRegistered(plugin.clone()))?;
            let declared = record
                .manifest
                .capabilities
                .iter()
                .find(|c| c.key() == key)
                .cloned();
            (declared, SystemTime::now())
        };
        match declared {
            Some(cap) => self.grant(plugin, &cap),
            None => {
                if let Some(reg) = &self.metrics {
                    entangle_observability::catalog::capability_denial(
                        reg,
                        key_family(key),
                        Denial::NotDeclared.metric_reason(),
                    );
                }
                self.audit.record(AuditEvent::CapabilityDenied {
                    plugin: plugin.clone(),
                    capability: Cow::Owned(key.to_owned()),
                    reason: Cow::Borrowed("not declared in manifest"),
                    at,
                });
                Err(BrokerError::CapabilityNotDeclared {
                    plugin: plugin.clone(),
                    capability: key.to_owned(),
                })
            }
        }
    }

    /// Resolve every capability the plugin's manifest declares (spec §4.5):
    /// each is granted, or denied with the reason (operator policy,
    /// revocation, tier ceiling). Every decision is audited.
    ///
    /// The kernel calls this once at load; the grants it issues are the
    /// plugin's standing grants, from which the runtimes derive what the
    /// plugin can reach (WASI preopens and socket rules for wasm, the OS
    /// sandbox profile for native). Fails only if the plugin is not
    /// registered.
    pub fn grant_declared(&self, plugin: &PluginId) -> Result<Resolution, BrokerError> {
        let declared = self
            .declared(plugin)
            .ok_or_else(|| BrokerError::PluginNotRegistered(plugin.clone()))?;
        let mut out = Resolution::default();
        for cap in declared {
            match self.grant(plugin, &cap) {
                Ok(g) => out.granted.push(g),
                Err(e @ BrokerError::PluginNotRegistered(_)) => return Err(e),
                Err(e) => out.denied.push((cap, e.to_string())),
            }
        }
        Ok(out)
    }

    /// Revoke the capability with manifest key `key` from `plugin` (spec
    /// §4.6, `entangle perms revoke`): every outstanding grant of it is
    /// withdrawn, and later requests are refused with
    /// [`BrokerError::CapabilityRevoked`] until the plugin is unloaded and
    /// loaded again. Idempotent; returns the grant ids withdrawn by this call.
    ///
    /// The capability must be declared ([`BrokerError::CapabilityNotDeclared`]
    /// otherwise), so a typo cannot pass for a revocation.
    pub fn revoke(&self, plugin: &PluginId, key: &str) -> Result<Vec<GrantId>, BrokerError> {
        let (withdrawn, newly, at) = {
            let plugins = self.plugins.read();
            let record = plugins
                .get(plugin)
                .ok_or_else(|| BrokerError::PluginNotRegistered(plugin.clone()))?;
            if !record.manifest.capabilities.iter().any(|c| c.key() == key) {
                return Err(BrokerError::CapabilityNotDeclared {
                    plugin: plugin.clone(),
                    capability: key.to_owned(),
                });
            }
            let mut table = record.table.lock();
            let newly = table.revoked.insert(key.to_owned());
            let mut withdrawn: Vec<GrantId> = table
                .grants
                .iter()
                .filter(|(_, k)| k.key() == key)
                .map(|(id, _)| *id)
                .collect();
            withdrawn.sort_unstable();
            for id in &withdrawn {
                table.grants.remove(id);
            }
            (withdrawn, newly, SystemTime::now())
        };
        if newly || !withdrawn.is_empty() {
            self.audit.record(AuditEvent::CapabilityRevoked {
                plugin: plugin.clone(),
                capability: Cow::Owned(key.to_owned()),
                grant_ids: withdrawn.clone(),
                at,
            });
        }
        Ok(withdrawn)
    }

    /// `true` while grant `grant_id` is outstanding for `plugin` (not
    /// released, revoked, or dropped with the plugin's registration).
    pub fn is_live(&self, plugin: &PluginId, grant_id: GrantId) -> bool {
        self.plugins
            .read()
            .get(plugin)
            .is_some_and(|r| r.table.lock().grants.contains_key(&grant_id))
    }

    /// The capabilities `plugin`'s manifest declares (with parameters), or
    /// `None` when it is not registered.
    pub fn declared(&self, plugin: &PluginId) -> Option<Vec<CapabilityKind>> {
        self.plugins
            .read()
            .get(plugin)
            .map(|r| r.manifest.capabilities.clone())
    }

    /// The registered plugin's effective tier, or `None`.
    pub fn effective_tier(&self, plugin: &PluginId) -> Option<Tier> {
        self.plugins
            .read()
            .get(plugin)
            .map(|r| r.manifest.effective_tier)
    }

    /// Every declared capability of `plugin` with its current
    /// [`GrantState`], in manifest order; `None` when it is not registered.
    /// Pure inspection: nothing is granted or audited.
    pub fn capability_report(&self, plugin: &PluginId) -> Option<Vec<CapabilityStatus>> {
        let plugins = self.plugins.read();
        let record = plugins.get(plugin)?;
        let table = record.table.lock();
        let ceiling = self
            .policy
            .check_plugin_load(record.manifest.effective_tier)
            .err();
        Some(
            record
                .manifest
                .capabilities
                .iter()
                .map(|cap| {
                    let key = cap.key();
                    let state = if table.revoked.contains(key.as_ref()) {
                        GrantState::Revoked
                    } else if let Some(e) = &ceiling {
                        GrantState::Denied {
                            reason: e.to_string(),
                        }
                    } else if let Some(detail) = self.operator_denial(&record.manifest, cap) {
                        GrantState::Denied {
                            reason: format!("operator policy (deny_capabilities = {detail:?})"),
                        }
                    } else {
                        let mut grant_ids: Vec<GrantId> = table
                            .grants
                            .iter()
                            .filter(|(_, k)| *k == cap)
                            .map(|(id, _)| *id)
                            .collect();
                        grant_ids.sort_unstable();
                        if grant_ids.is_empty() {
                            GrantState::NotGranted
                        } else {
                            GrantState::Granted { grant_ids }
                        }
                    };
                    CapabilityStatus {
                        capability: cap.clone(),
                        state,
                    }
                })
                .collect(),
        )
    }

    /// Why the operator's deny list refuses `cap` to the plugin whose
    /// manifest is `manifest`: the matching pattern, or `None`.
    ///
    /// A native plugin's OS sandbox can only allow or forbid IP networking
    /// as a whole, so for it `net.lan` and `net.wan` are one authority: a
    /// pattern denying either denies both. Otherwise denying `net.wan` would
    /// not stop the WAN egress a granted `net.lan` gives a native plugin
    /// (wasm plugins' rules are per address and keep the other one).
    fn operator_denial(&self, manifest: &ValidatedManifest, cap: &CapabilityKind) -> Option<String> {
        if let Some(p) = self.policy.denies(cap) {
            return Some(p.as_str().to_owned());
        }
        let is_net = matches!(cap, CapabilityKind::NetLan | CapabilityKind::NetWan { .. });
        if manifest.runtime != Runtime::Native || !is_net {
            return None;
        }
        [
            CapabilityKind::NetLan,
            CapabilityKind::NetWan { hosts: Vec::new() },
        ]
        .iter()
        .find_map(|other| self.policy.denies(other))
        .map(|p| {
            format!(
                "{} (a native sandbox cannot separate net.lan from net.wan)",
                p.as_str()
            )
        })
    }

    /// The broker's decision for `requested`, issuing the grant (under the
    /// plugin's table lock) when every check passes.
    fn decide(&self, record: &PluginRecord, requested: &CapabilityKind) -> Result<GrantId, Denial> {
        // Deny-by-default: requested kind must be present in manifest capabilities.
        if !record.manifest.capabilities.iter().any(|c| c == requested) {
            return Err(Denial::NotDeclared);
        }
        // Tier ceiling (§9.4.1): enforced at registration, re-checked per
        // decision so a grant can never outlive a policy that forbids it.
        if let Err(e) = self
            .policy
            .check_plugin_load(record.manifest.effective_tier)
        {
            return Err(Denial::TierCeiling(e.to_string()));
        }
        // Operator deny list (§4.5).
        if let Some(detail) = self.operator_denial(&record.manifest, requested) {
            return Err(Denial::OperatorPolicy(detail));
        }
        let mut table = record.table.lock();
        if table.revoked.contains(requested.key().as_ref()) {
            return Err(Denial::Revoked);
        }
        let gid = self.next_grant_id.fetch_add(1, Ordering::Relaxed);
        table.grants.insert(gid, requested.clone());
        Ok(gid)
    }

    /// Audit + count a decision made by [`Broker::decide`] and turn it into
    /// the public result.
    fn record_decision(
        &self,
        plugin: &PluginId,
        requested: &CapabilityKind,
        decision: Result<GrantId, Denial>,
        at: SystemTime,
    ) -> Result<GrantedCapability, BrokerError> {
        let capability = format_cap(requested);
        if let Some(reg) = &self.metrics {
            match &decision {
                Ok(_) => {
                    entangle_observability::catalog::capability_grant(reg, cap_kind(requested))
                }
                Err(d) => entangle_observability::catalog::capability_denial(
                    reg,
                    cap_kind(requested),
                    d.metric_reason(),
                ),
            }
        }
        match decision {
            Err(denial) => {
                self.audit.record(AuditEvent::CapabilityDenied {
                    plugin: plugin.clone(),
                    capability: capability.clone(),
                    reason: denial.audit_reason(),
                    at,
                });
                Err(denial.into_error(plugin, capability.into_owned()))
            }
            Ok(gid) => {
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
            let mut table = record.table.lock();
            table
                .grants
                .remove(&grant_id)
                .map(|k| (k, SystemTime::now()))
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
        let started = std::time::Instant::now();
        let result =
            self.verify_biscuit(requested, biscuit_bytes, local_peer_id, cross_node_policy);
        if let Some(reg) = &self.metrics {
            entangle_observability::catalog::biscuit_verification(
                reg,
                result.is_ok(),
                started.elapsed().as_secs_f64(),
            );
            if result.is_err() {
                entangle_observability::catalog::capability_denial(
                    reg,
                    cap_kind(requested),
                    "biscuit_invalid",
                );
            }
        }
        result?;

        // 3. Biscuit is valid — ALSO enforce manifest deny-by-default.
        //    A biscuit grants are never a bypass for the manifest layer.
        self.grant(plugin, requested)
    }

    /// Steps 1 and 2 of [`Broker::grant_with_biscuit`]: signature, expiry,
    /// peer binding and capability surface.
    fn verify_biscuit(
        &self,
        requested: &CapabilityKind,
        biscuit_bytes: &[u8],
        local_peer_id: PeerId,
        cross_node_policy: &CrossNodePolicy,
    ) -> Result<(), BrokerError> {
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
        let cap_str = biscuit_surface(requested);
        verifier::verify(
            &biscuit,
            &verifier::VerifyContext {
                now_unix_secs: now_secs() as i64,
                local_peer_id,
            },
            &cap_str,
        )
        .map_err(|e| BrokerError::BiscuitVerify(e.to_string()))?;
        Ok(())
    }

    /// Return all outstanding grants for a plugin.
    pub fn snapshot_grants(&self, plugin: &PluginId) -> Vec<GrantedCapability> {
        self.plugins
            .read()
            .get(plugin)
            .map(|r| {
                r.table
                    .lock()
                    .grants
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

/// Why [`Broker::decide`] refused a capability.
enum Denial {
    NotDeclared,
    TierCeiling(String),
    OperatorPolicy(String),
    Revoked,
}

impl Denial {
    /// The `reason` label of `entangle_capability_denials_total`.
    fn metric_reason(&self) -> &'static str {
        match self {
            Denial::NotDeclared => "not_declared",
            Denial::TierCeiling(_) => "tier_ceiling",
            Denial::OperatorPolicy(_) => "operator_policy",
            Denial::Revoked => "revoked",
        }
    }

    fn audit_reason(&self) -> Cow<'static, str> {
        match self {
            Denial::NotDeclared => Cow::Borrowed("not declared in manifest"),
            Denial::TierCeiling(e) => Cow::Owned(format!("tier ceiling: {e}")),
            Denial::OperatorPolicy(p) => {
                Cow::Owned(format!("operator policy (deny_capabilities = {p:?})"))
            }
            Denial::Revoked => Cow::Borrowed("revoked by operator"),
        }
    }

    fn into_error(self, plugin: &PluginId, capability: String) -> BrokerError {
        let plugin = plugin.clone();
        match self {
            Denial::NotDeclared => BrokerError::CapabilityNotDeclared { plugin, capability },
            Denial::TierCeiling(detail) => BrokerError::TierCeiling(Box::new(Refusal {
                plugin,
                capability,
                detail,
            })),
            Denial::OperatorPolicy(detail) => {
                BrokerError::CapabilityDeniedByPolicy(Box::new(Refusal {
                    plugin,
                    capability,
                    detail,
                }))
            }
            Denial::Revoked => BrokerError::CapabilityRevoked { plugin, capability },
        }
    }
}

/// The fixed-cardinality metric label for a capability kind.
fn cap_kind(c: &CapabilityKind) -> &'static str {
    c.family()
}

/// [`CapabilityKind::family`] for a bare manifest key, so a denial for an
/// undeclared key (which has no `CapabilityKind`) is labelled the same way.
fn key_family(key: &str) -> &'static str {
    const FIXED: &[&str] = &[
        "compute.cpu",
        "compute.gpu",
        "compute.npu",
        "storage.local",
        "net.lan",
        "net.wan",
        "mesh.peer",
        "agent.invoke",
        "host.docker-socket",
    ];
    if let Some(k) = FIXED.iter().find(|k| **k == key) {
        k
    } else if key.starts_with("storage.share.") {
        "storage.share"
    } else if key.starts_with("custom.") {
        "custom"
    } else {
        "unknown"
    }
}

/// The capability surface a cross-node biscuit must carry for `c`.
///
/// Deliberately independent of the audit rendering ([`format_cap`]): it is a
/// wire contract with biscuits minted by other nodes, so it keeps the
/// pre-parameter forms (`net.wan`, `storage.local[Plugin]`) — the manifest
/// still bounds the parameters, since a biscuit grant also passes
/// [`Broker::grant`].
fn biscuit_surface(c: &CapabilityKind) -> Cow<'static, str> {
    match c {
        CapabilityKind::StorageLocal { scope, .. } => {
            Cow::Owned(format!("storage.local[{scope:?}]"))
        }
        CapabilityKind::NetWan { .. } => Cow::Borrowed("net.wan"),
        // Biscuits minted so far carry `custom.` + the stored name, and the
        // manifest stores the full key (`custom.x`): keep that wire form.
        CapabilityKind::Custom(s) => Cow::Owned(format!("custom.{s}")),
        other => format_cap(other),
    }
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
        StorageLocal { scope, mode } => Cow::Owned(format!("storage.local[{scope:?},{mode:?}]")),
        StorageShare { name, mode } => Cow::Owned(format!("storage.share.{name}[{mode:?}]")),
        NetLan => Cow::Borrowed("net.lan"),
        NetWan { .. } => Cow::Owned(format!("net.wan[{}]", c.params())),
        MeshPeer => Cow::Borrowed("mesh.peer"),
        AgentInvoke => Cow::Borrowed("agent.invoke"),
        HostDockerSocket => Cow::Borrowed("host.docker-socket"),
        // The manifest key (`custom.x`), whether or not the stored name
        // carries the `custom.` prefix — the same name `revoke` and
        // `grant_by_key` audit, so events for one capability correlate.
        Custom(_) => c.key(),
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
