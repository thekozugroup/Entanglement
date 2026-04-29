//! Daemon configuration — mirrors the CLI's `~/.entangle/config.toml` schema.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level daemon configuration (deserialized from `~/.entangle/config.toml`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Runtime-specific tuning knobs.
    pub runtime: RuntimeConfig,
}

/// Runtime-related configuration knobs.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeConfig {
    /// Maximum tier plugins may declare. Defaults to `"native"`.
    pub max_tier: String,
    /// Whether multi-node mesh mode is active.
    pub multi_node: bool,
    /// Lifecycle event bus capacity (number of buffered envelopes).
    pub bus_capacity: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            max_tier: "native".to_owned(),
            multi_node: false,
            bus_capacity: 1024,
        }
    }
}

/// Load configuration from a TOML file, or return defaults if the file does
/// not exist. Returns an error only on parse failures.
pub fn load_config(path: &std::path::Path) -> anyhow::Result<Config> {
    if !path.exists() {
        tracing::debug!(path = %path.display(), "config file absent — using defaults");
        return Ok(Config::default());
    }
    let raw = std::fs::read_to_string(path)?;
    let cfg: Config = toml::from_str(&raw)?;
    Ok(cfg)
}

/// Resolve the default socket path: `~/.entangle/sock`.
pub fn default_socket_path() -> PathBuf {
    directories::BaseDirs::new()
        .map(|b| b.home_dir().join(".entangle").join("sock"))
        .unwrap_or_else(|| PathBuf::from("/tmp/entangled.sock"))
}

/// Resolve the default config directory: `~/.entangle/`.
pub fn default_config_dir() -> PathBuf {
    directories::BaseDirs::new()
        .map(|b| b.home_dir().join(".entangle"))
        .unwrap_or_else(|| PathBuf::from("/tmp/.entangle"))
}
