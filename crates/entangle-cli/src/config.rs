//! `~/.entangle/config.toml` schema, load, and save helpers.
//!
//! Per spec §9.1, the canonical install path is `~/.entangle/`. We prefer
//! `${HOME}/.entangle/` when `$HOME` is set; only fall back to the
//! platform-specific `directories` path if `$HOME` is absent.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub mesh: MeshConfig,
    #[serde(default)]
    pub security: SecurityConfig,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MeshConfig {
    /// Active transport backends. Phase 1 only supports "local".
    #[serde(default)]
    pub transports: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Maximum plugin tier accepted at runtime (1..=5).
    #[serde(default = "default_max_tier")]
    pub max_tier_allowed: u8,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_tier_allowed: default_max_tier(),
        }
    }
}

fn default_max_tier() -> u8 {
    5
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// Returns `~/.entangle/` if `$HOME` is set, else uses the `directories`
/// platform path. Spec §9.1 mandates `~/.entangle/` on Linux/macOS.
pub fn entangle_dir() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".entangle");
    }
    // Fallback: use directories crate (Windows or missing $HOME).
    directories::ProjectDirs::from("dev", "entanglement-dev", "entangle")
        .map(|p| p.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".entangle"))
}

pub fn config_path() -> PathBuf {
    entangle_dir().join("config.toml")
}

pub fn identity_path() -> PathBuf {
    entangle_dir().join("identity.key")
}

pub fn keyring_path() -> PathBuf {
    entangle_dir().join("keyring.toml")
}

// ---------------------------------------------------------------------------
// I/O
// ---------------------------------------------------------------------------

/// Load config from `path`. Returns `Ok(Default::default())` if file is absent.
pub fn load(path: &Path) -> anyhow::Result<Config> {
    if !path.exists() {
        return Ok(Config::default());
    }
    let raw = std::fs::read_to_string(path)?;
    let cfg: Config = toml::from_str(&raw)?;
    Ok(cfg)
}

/// Serialize `c` to `path`, creating parent directories as needed.
pub fn save(path: &Path, c: &Config) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let raw = toml::to_string_pretty(c)?;
    std::fs::write(path, raw)?;
    Ok(())
}
