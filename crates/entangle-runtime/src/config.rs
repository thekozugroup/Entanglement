//! Shared on-disk operator configuration for the daemon and CLI.

use entangle_types::tier::Tier;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level daemon configuration (deserialized from `~/.entangle/config.toml`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Runtime tuning and daemon startup settings.
    pub runtime: RuntimeConfig,
    /// Mesh transport configuration.
    pub mesh: MeshConfig,
    /// Operator security policy.
    pub security: SecurityConfig,
    /// Cross-node scheduler settings (daemon-only section).
    ///
    /// Inert unless `[mesh] transports` contains `"iroh"` or `"tailscale"`, so a config
    /// written by an older CLI — which omits this section entirely — leaves
    /// the daemon single-machine, exactly as before.
    pub scheduler: SchedulerConfig,
}

impl Config {
    /// Translate operator settings into the policy used for plugin execution.
    pub fn kernel_config(&self) -> crate::KernelConfig {
        crate::KernelConfig {
            max_tier_allowed: self.security.max_tier_allowed,
            multi_node: self.mesh.multi_node,
            bus_capacity: self.runtime.bus_capacity,
        }
    }

    /// Check a prospective installation against the operator's tier ceiling.
    pub fn check_plugin_tier(&self, tier: Tier) -> Result<(), entangle_broker::PolicyError> {
        entangle_broker::BrokerPolicy {
            max_tier_allowed: self.security.max_tier_allowed,
            ..Default::default()
        }
        .check_plugin_load(tier)
    }
}

/// Cross-node scheduler settings (daemon-only).
///
/// This section only matters when `"iroh"` or `"tailscale"` appears in `[mesh] transports`.
/// Turning that on does two things, and both are gated on the peer store:
/// this node begins **serving** work to peers in its allowlist, and it may
/// **send** work to the peers listed here.
///
/// ```toml
/// [mesh]
/// transports = ["local", "iroh"]
///
/// [scheduler]
/// bind = "0.0.0.0:0"
/// peers = ["<pubkey-hex>@192.0.2.7:41641"]
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SchedulerConfig {
    /// UDP socket for the scheduler QUIC endpoint. `:0` picks an ephemeral
    /// port. In Tailscale-only mode an unspecified IP selects the local
    /// tailnet IP of the same address family. A concrete IP must belong
    /// to the local tailnet node.
    pub bind: String,
    /// Long addresses (`<pubkey-hex>@host:port`) of peers this node may
    /// dispatch work to.
    ///
    /// An entry is used only if that peer is *also* trusted in the peer
    /// store, so listing an address here does not by itself grant anything.
    pub peers: Vec<String>,
    /// Explicit associations between Tailscale stable node IDs and paired
    /// Entanglement keys. Used only when the Tailscale transport is enabled.
    pub tailnet_peers: Vec<TailnetPeerConfig>,
    /// Allow Iroh relay fallback when the Iroh transport is enabled.
    /// Tailscale-only endpoints always disable Iroh relays.
    pub relay: bool,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:0".to_owned(),
            peers: Vec::new(),
            tailnet_peers: Vec::new(),
            relay: true,
        }
    }
}

/// One `[[scheduler.tailnet_peers]]` route.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TailnetPeerConfig {
    /// Stable node ID from the peer's Tailscale status record (`ID`).
    pub node_id: String,
    /// Hex-encoded Entanglement Ed25519 public key, as in a long address.
    pub public_key: String,
    /// UDP scheduler port configured on the remote Entanglement daemon.
    pub port: std::num::NonZeroU16,
}

/// Mesh-layer configuration.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MeshConfig {
    /// Active transport backends. `"local"` enables mDNS discovery, `"iroh"`
    /// enables static QUIC routes, and `"tailscale"` enables tailnet routes.
    pub transports: Vec<String>,
    /// When `true` the daemon requires at least one trusted peer before
    /// starting (spec §11 #16, enforced via ENTANGLE-E0050 at startup).
    pub multi_node: bool,
}

/// Security policy configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    /// Maximum tier plugins may declare (1..=5). Defaults to tier 5 (native),
    /// matching the CLI default.
    pub max_tier_allowed: Tier,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_tier_allowed: Tier::Native,
        }
    }
}

/// Runtime-related configuration knobs (daemon-only).
///
/// Note: `multi_node` and `max_tier` used to live here but were never the
/// operator-facing knobs — the CLI writes `[mesh] multi_node` and
/// `[security] max_tier_allowed`. Those sections are now authoritative; a
/// leftover key here fails loudly thanks to `deny_unknown_fields`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeConfig {
    /// Lifecycle event bus capacity (number of buffered envelopes).
    pub bus_capacity: usize,
    /// Optional loopback HTTP listener for Prometheus scrapes.
    pub metrics_bind: Option<std::net::SocketAddr>,
    /// Absolute paths to signed plugin package directories loaded at startup.
    pub plugins: Vec<PathBuf>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            bus_capacity: 1024,
            metrics_bind: None,
            plugins: Vec::new(),
        }
    }
}

/// Load configuration from a TOML file, or return defaults if the file does
/// not exist. Report other read errors and malformed configuration.
pub fn load_config(path: &std::path::Path) -> anyhow::Result<Config> {
    let raw = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            tracing::debug!(path = %path.display(), "config file absent — using defaults");
            return Ok(Config::default());
        }
        Err(error) => return Err(error.into()),
    };
    let cfg: Config = toml::from_str(&raw)?;
    Ok(cfg)
}
