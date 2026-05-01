//! Daemon-wide broker policy — tier ceiling and multi-node invariants.
//!
//! See spec §9.4 (`max_tier_allowed`) and §11 #16 (multi-node allowlist).

use entangle_biscuits::PublicKey;
use entangle_types::tier::Tier;

/// Daemon-wide policy enforced by the [`crate::Broker`].
#[derive(Clone, Debug)]
pub struct BrokerPolicy {
    /// §9.4.1 — daemon refuses to load any plugin with effective_tier above this.
    pub max_tier_allowed: Tier,

    /// §11 #16 — multi-node mode requires a populated peer allowlist before
    /// mesh transports activate. Single-node mode is fine.
    pub multi_node: bool,

    /// Whether the peer allowlist has been populated before mesh activation.
    pub peer_allowlist_populated: bool,
}

impl Default for BrokerPolicy {
    fn default() -> Self {
        Self {
            max_tier_allowed: Tier::Native, // permissive default; daemon may override
            multi_node: false,
            peer_allowlist_populated: false,
        }
    }
}

/// Policy for cross-node biscuit-based capability grants.
///
/// Populated from `~/.entangle/keyring.toml` (publisher keys for signed plugins)
/// and `~/.entangle/peers.toml` (paired peer pubkeys). Any biscuit signed by
/// one of the registered trust roots is considered valid for cross-node grants.
#[derive(Clone, Default)]
pub struct CrossNodePolicy {
    /// Trust roots: any biscuit signed by one of these public keys is acceptable.
    pub trust_roots: Vec<PublicKey>,
}

impl CrossNodePolicy {
    /// Create an empty policy (no trust roots — all cross-node grants will be denied).
    pub fn empty() -> Self {
        Self {
            trust_roots: vec![],
        }
    }

    /// Add a trust root public key.
    pub fn with_root(mut self, key: PublicKey) -> Self {
        self.trust_roots.push(key);
        self
    }
}

/// Errors produced when policy checks fail.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// ENTANGLE-E0043: the plugin's effective tier exceeds the daemon ceiling.
    #[error("ENTANGLE-E0043: plugin tier {plugin:?} exceeds daemon ceiling {ceiling:?}")]
    TierAboveCeiling {
        /// The plugin's effective tier.
        plugin: Tier,
        /// The daemon's configured ceiling.
        ceiling: Tier,
    },

    /// ENTANGLE-E0050: daemon is in multi-node mode but peer allowlist is empty.
    #[error("ENTANGLE-E0050: daemon is in multi-node mode but peer allowlist is empty")]
    MultiNodeNoAllowlist,
}

impl BrokerPolicy {
    /// Construct a `BrokerPolicy` from live state.
    ///
    /// `peer_allowlist_populated` is derived from [`entangle_peers::PeerStore::is_empty`]
    /// so callers cannot accidentally supply a stale bool.
    pub fn new(
        max_tier: entangle_types::tier::Tier,
        multi_node: bool,
        peer_store: &entangle_peers::PeerStore,
    ) -> Self {
        Self {
            max_tier_allowed: max_tier,
            multi_node,
            peer_allowlist_populated: !peer_store.is_empty(),
        }
    }

    /// Called at plugin load time. Returns `Err` if loading must be refused.
    ///
    /// Enforces §9.4.1: effective tier must not exceed [`Self::max_tier_allowed`].
    pub fn check_plugin_load(&self, effective_tier: Tier) -> Result<(), PolicyError> {
        if effective_tier > self.max_tier_allowed {
            return Err(PolicyError::TierAboveCeiling {
                plugin: effective_tier,
                ceiling: self.max_tier_allowed,
            });
        }
        Ok(())
    }

    /// Called at daemon startup before any mesh transport is enabled.
    ///
    /// Enforces §11 #16: in multi-node mode the peer allowlist must be populated.
    pub fn check_startup(&self) -> Result<(), PolicyError> {
        if self.multi_node && !self.peer_allowlist_populated {
            return Err(PolicyError::MultiNodeNoAllowlist);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_permissive() {
        let p = BrokerPolicy::default();
        assert_eq!(p.max_tier_allowed, Tier::Native);
        assert!(!p.multi_node);
    }

    #[test]
    fn check_startup_single_node_ok() {
        let p = BrokerPolicy::default();
        assert!(p.check_startup().is_ok());
    }

    #[test]
    fn check_startup_multi_node_no_allowlist_errors() {
        let p = BrokerPolicy {
            multi_node: true,
            peer_allowlist_populated: false,
            ..Default::default()
        };
        assert!(matches!(
            p.check_startup(),
            Err(PolicyError::MultiNodeNoAllowlist)
        ));
    }

    #[test]
    fn check_startup_multi_node_with_allowlist_ok() {
        let p = BrokerPolicy {
            multi_node: true,
            peer_allowlist_populated: true,
            ..Default::default()
        };
        assert!(p.check_startup().is_ok());
    }
}
