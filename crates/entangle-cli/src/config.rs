//! `~/.entangle/config.toml` schema, load, and save helpers.
//!
//! Per spec §9.1, the canonical install path is `~/.entangle/`. We prefer
//! `${HOME}/.entangle/` when `$HOME` is set; only fall back to the
//! platform-specific `directories` path if `$HOME` is absent.

use std::path::{Path, PathBuf};

pub use entangle_runtime::config::{
    load_config as load, MeshConfig, SchedulerConfig, SecurityConfig,
};
use serde::Serialize;

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/// The sections written on first initialization. Later loads use the full shared schema.
#[derive(Serialize)]
pub struct InitialConfig {
    pub mesh: MeshConfig,
    pub security: SecurityConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduler: Option<SchedulerConfig>,
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

/// Start the short-lived CLI worker with the same execution policy as the daemon.
pub fn local_kernel() -> anyhow::Result<entangle_runtime::Kernel> {
    let cfg = load(&config_path())?;
    Ok(entangle_runtime::Kernel::from_keyring_file(
        cfg.kernel_config(),
        keyring_path(),
    )?)
}

/// Serialize `c` to `path`, creating parent directories as needed.
pub fn save(path: &Path, c: &InitialConfig) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let raw = toml::to_string_pretty(c)?;
    std::fs::write(path, raw)?;
    Ok(())
}
