//! Error types for the capability broker.

use entangle_types::{plugin_id::PluginId, tier::Tier};

/// Top-level error type for all broker operations.
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    /// A policy check failed (tier ceiling or startup invariant).
    #[error("policy: {0}")]
    Policy(#[from] crate::policy::PolicyError),

    /// ENTANGLE-E0042: the plugin declared a tier below what its capabilities require.
    ///
    /// Note: this is ordinarily caught by `entangle-manifest::validate` before the
    /// manifest reaches the broker. This variant exists as a belt-and-suspenders
    /// defence for any code path that bypasses the manifest layer.
    #[error(
        "ENTANGLE-E0042: plugin '{plugin}' declared tier {declared:?} below implied \
         tier {implied:?} via capability '{capability}'"
    )]
    TierBelowCapability {
        /// The plugin that has the inconsistent manifest.
        plugin: PluginId,
        /// The tier the plugin declared.
        declared: Tier,
        /// The tier implied by the offending capability.
        implied: Tier,
        /// The name of the capability that requires the higher tier.
        capability: String,
    },

    /// ENTANGLE-E0120: the requested capability was not declared in the plugin manifest.
    ///
    /// Enforces the no-ambient-authority invariant (spec §11).
    #[error(
        "ENTANGLE-E0120: capability '{capability}' not declared by plugin '{plugin}' \
         — denied (no ambient authority)"
    )]
    CapabilityNotDeclared {
        /// The requesting plugin.
        plugin: PluginId,
        /// The capability that was requested but not declared.
        capability: String,
    },

    /// ENTANGLE-E0121: the plugin has been unloaded; the capability grant is stale.
    #[error(
        "ENTANGLE-E0121: plugin '{plugin}' has been unloaded; capability \
         '{capability}' is no longer valid"
    )]
    PluginUnloaded {
        /// The plugin that was unloaded.
        plugin: PluginId,
        /// The capability whose grant is now stale.
        capability: String,
    },

    /// A plugin ID was not found in the broker registry.
    #[error("plugin not registered: {0}")]
    PluginNotRegistered(PluginId),

    /// ENTANGLE-E0123: a plugin with this id is already registered.
    ///
    /// Registration never overwrites: silently replacing a live record would
    /// drop its outstanding grants without `CapabilityReleased` audit events.
    /// Unregister the existing plugin first.
    #[error("ENTANGLE-E0123: plugin already registered: {0}")]
    AlreadyRegistered(PluginId),

    /// ENTANGLE-E0124: the operator's `[security] deny_capabilities` policy
    /// refuses this capability (spec §4.5), whatever the manifest declares.
    #[error(
        "ENTANGLE-E0124: capability '{capability}' denied to plugin '{plugin}' by operator \
         policy (deny_capabilities = {pattern:?})"
    )]
    CapabilityDeniedByPolicy {
        /// The requesting plugin.
        plugin: PluginId,
        /// The refused capability.
        capability: String,
        /// The deny pattern that matched.
        pattern: String,
    },

    /// ENTANGLE-E0125: the capability was revoked from this plugin
    /// (`entangle perms revoke`, spec §4.6); it stays refused until the
    /// plugin is reloaded.
    #[error("ENTANGLE-E0125: capability '{capability}' was revoked from plugin '{plugin}'")]
    CapabilityRevoked {
        /// The requesting plugin.
        plugin: PluginId,
        /// The revoked capability.
        capability: String,
    },

    /// ENTANGLE-E0127: the plugin's effective tier is above the daemon's
    /// `max_tier_allowed`, so none of its capabilities may be granted
    /// (spec §4.5 "plugin tier within global cap?").
    #[error("ENTANGLE-E0127: capability '{capability}' denied to plugin '{plugin}': {reason}")]
    TierCeiling {
        /// The requesting plugin.
        plugin: PluginId,
        /// The refused capability.
        capability: String,
        /// The ceiling violation.
        reason: String,
    },

    /// ENTANGLE-E0411: biscuit verification failed.
    ///
    /// Returned by [`crate::Broker::grant_with_biscuit`] when no trust root
    /// accepts the presented token, or when the token's claims (expiry, peer,
    /// capability surface) do not satisfy the requirements.
    #[error("ENTANGLE-E0411: biscuit verification failed: {0}")]
    BiscuitVerify(String),
}
