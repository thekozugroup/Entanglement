//! Daemon-wide broker policy — tier ceiling, operator capability deny list,
//! and multi-node invariants.
//!
//! See spec §9.4 (`max_tier_allowed`), §4.5 (capability resolution) and
//! §11 #16 (multi-node allowlist).

use entangle_biscuits::PublicKey;
use entangle_types::{
    capability::{is_valid_share_name, CapabilityKind},
    tier::Tier,
};

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

    /// `[security] deny_capabilities` — capabilities the operator refuses to
    /// grant to any plugin, whatever its manifest declares (spec §4.5). A
    /// plugin that declares one still loads; that capability is simply never
    /// granted (audited as a denial with reason `operator_policy`).
    pub denied_capabilities: Vec<CapabilityPattern>,
}

impl Default for BrokerPolicy {
    fn default() -> Self {
        Self {
            max_tier_allowed: Tier::Native, // permissive default; daemon may override
            multi_node: false,
            peer_allowlist_populated: false,
            denied_capabilities: Vec::new(),
        }
    }
}

/// One `[security] deny_capabilities` entry: a pattern over capability keys
/// (see [`CapabilityKind::key`]).
///
/// Three forms:
/// - an exact key: `net.wan`, `storage.local`, `storage.share.photos`,
///   `custom.telemetry`;
/// - a family prefix ending in `.*`: `net.*`, `storage.*`,
///   `storage.share.*`, `compute.*`, `custom.*`;
/// - `*` — every capability.
///
/// Patterns are validated when parsed, so a typo such as `net.wann` is a
/// configuration error instead of a deny rule that silently matches nothing.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CapabilityPattern(String);

/// Fixed capability keys (everything except `storage.share.<name>` and
/// `custom.<x>`).
const FIXED_KEYS: &[&str] = &[
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

/// Prefixes a `<prefix>.*` pattern may use.
const FAMILY_PREFIXES: &[&str] = &[
    "compute",
    "storage",
    "storage.share",
    "net",
    "mesh",
    "agent",
    "host",
    "custom",
];

impl CapabilityPattern {
    /// The pattern text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `true` when this pattern matches the capability key `key`.
    pub fn matches_key(&self, key: &str) -> bool {
        match self.0.strip_suffix(".*") {
            _ if self.0 == "*" => true,
            Some(prefix) => key
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('.') && rest.len() > 1),
            None => self.0 == key,
        }
    }

    /// `true` when this pattern matches `cap`.
    pub fn matches(&self, cap: &CapabilityKind) -> bool {
        self.matches_key(&cap.key())
    }
}

impl std::str::FromStr for CapabilityPattern {
    type Err = PolicyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = |reason: &str| PolicyError::InvalidCapabilityPattern {
            pattern: s.to_owned(),
            reason: reason.to_owned(),
        };
        let ok = if s == "*" {
            true
        } else if let Some(prefix) = s.strip_suffix(".*") {
            FAMILY_PREFIXES.contains(&prefix)
        } else if let Some(name) = s.strip_prefix("storage.share.") {
            is_valid_share_name(name)
        } else if let Some(name) = s.strip_prefix("custom.") {
            !name.is_empty() && !name.contains('*') && !name.chars().any(char::is_whitespace)
        } else {
            FIXED_KEYS.contains(&s)
        };
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(invalid(
                "expected a capability key (e.g. `net.wan`, `storage.share.photos`), \
                 a family prefix ending in `.*` (e.g. `storage.share.*`), or `*`",
            ))
        }
    }
}

impl std::fmt::Display for CapabilityPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Serialises as the pattern text, so `deny_capabilities` round-trips
/// through `config.toml` as a list of strings.
impl serde::Serialize for CapabilityPattern {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

/// Parses and validates the pattern text: an invalid pattern is a
/// configuration error (`ENTANGLE-E0126`), never a rule that matches nothing.
impl<'de> serde::Deserialize<'de> for CapabilityPattern {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
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

    /// ENTANGLE-E0126: a `[security] deny_capabilities` entry is not a valid
    /// capability pattern.
    #[error(
        "ENTANGLE-E0126: invalid capability pattern {pattern:?} in deny_capabilities: {reason}"
    )]
    InvalidCapabilityPattern {
        /// The rejected pattern.
        pattern: String,
        /// Why it was rejected.
        reason: String,
    },
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
            denied_capabilities: Vec::new(),
        }
    }

    /// The first operator deny pattern matching `cap`, if any.
    pub fn denies(&self, cap: &CapabilityKind) -> Option<&CapabilityPattern> {
        let key = cap.key();
        self.denied_capabilities
            .iter()
            .find(|p| p.matches_key(&key))
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
    fn capability_patterns_parse_and_match() {
        let p = |s: &str| s.parse::<CapabilityPattern>().unwrap();
        assert!(p("net.wan").matches_key("net.wan"));
        assert!(!p("net.wan").matches_key("net.lan"));
        assert!(p("net.*").matches_key("net.wan"));
        assert!(p("net.*").matches_key("net.lan"));
        assert!(!p("net.*").matches_key("network.x"));
        assert!(p("storage.share.*").matches_key("storage.share.photos"));
        assert!(!p("storage.share.*").matches_key("storage.local"));
        assert!(p("storage.*").matches_key("storage.local"));
        assert!(p("storage.*").matches_key("storage.share.photos"));
        assert!(p("storage.share.photos").matches_key("storage.share.photos"));
        assert!(!p("storage.share.photos").matches_key("storage.share.inbox"));
        assert!(p("custom.*").matches_key("custom.telemetry"));
        assert!(p("*").matches_key("compute.cpu"));

        for bad in [
            "",
            "net.wann",
            "net",
            "net.",
            "*.wan",
            "net.w*",
            "storage.share./",
            "storage.share...",
            "custom.",
            "custom.a b",
            "custom.*x",
            "bogus.*",
            "NET.WAN",
        ] {
            let err = bad.parse::<CapabilityPattern>().unwrap_err();
            assert!(err.to_string().contains("ENTANGLE-E0126"), "{bad:?}: {err}");
        }
    }

    #[test]
    fn denies_reports_the_matching_pattern() {
        let policy = BrokerPolicy {
            denied_capabilities: vec![
                "storage.share.*".parse().unwrap(),
                "net.wan".parse().unwrap(),
            ],
            ..Default::default()
        };
        let wan = CapabilityKind::NetWan { hosts: vec![] };
        assert_eq!(policy.denies(&wan).map(|p| p.as_str()), Some("net.wan"));
        assert!(policy.denies(&CapabilityKind::NetLan).is_none());
        let share = CapabilityKind::StorageShare {
            name: "photos".into(),
            mode: entangle_types::capability::ShareMode::Ro,
        };
        assert_eq!(
            policy.denies(&share).map(|p| p.as_str()),
            Some("storage.share.*")
        );
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
