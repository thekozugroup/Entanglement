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
    /// `[wrappers]` — the opt-in shell shim (spec §8.3).
    #[serde(default, skip_serializing_if = "WrappersConfig::is_default")]
    pub wrappers: WrappersConfig,
    /// `[plugins]` — operator state about plugins.
    #[serde(default, skip_serializing_if = "PluginsConfig::is_default")]
    pub plugins: PluginsConfig,
}

/// `[runtime] aot_cache` from the config file at `path` (default `true`).
///
/// `[runtime]` is the daemon's section and deliberately not part of the
/// CLI's [`Config`] (the CLI never writes it); the `--allow-local` kernel
/// only reads this one key, so it shares the daemon's AOT cache unless the
/// operator turned it off.
pub fn runtime_aot_cache(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| text.parse::<toml::Table>().ok())
        .and_then(|t| t.get("runtime")?.get("aot_cache")?.as_bool())
        .unwrap_or(true)
}

/// `[wrappers]` section.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappersConfig {
    /// `true` once the operator ran `entangle wrapper enable`; `false` or
    /// absent means not opted in (also what `entangle wrapper disable` records).
    #[serde(default)]
    pub install: bool,
}

impl WrappersConfig {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// `[plugins]` section.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginsConfig {
    /// Plugin ids unloaded by a `max_tier_allowed` lowering (spec §9.4.1
    /// step 4) and not to be loaded again until removed from this list.
    #[serde(default)]
    pub disabled: Vec<String>,
}

impl PluginsConfig {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MeshConfig {
    /// Active transport backends. Phase 1 only supports "local".
    #[serde(default)]
    pub transports: Vec<String>,
    /// When `true` the daemon requires at least one trusted peer before starting
    /// (spec §11 #16).  Relevant to `doctor` check #5.
    #[serde(default)]
    pub multi_node: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Maximum plugin tier accepted at runtime (1..=5). `4` disables tier-5
    /// native plugins globally; `3` disables every native plugin.
    #[serde(default = "default_max_tier")]
    pub max_tier_allowed: u8,
    /// Run native plugins without an OS sandbox on a host that has none.
    /// Default `false` (refused with ENTANGLE-E0700).
    #[serde(default)]
    pub allow_unsandboxed_native: bool,
    /// Capabilities never granted to any plugin (spec §4.5), e.g.
    /// `["net.wan", "storage.share.*"]`. A plugin declaring one loads
    /// without it. Validated when a kernel is built (`ENTANGLE-E0126`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_capabilities: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_tier_allowed: default_max_tier(),
            allow_unsandboxed_native: false,
            deny_capabilities: Vec::new(),
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

/// Release-key keyring: a distinct trust class from the plugin-publisher
/// keyring, so a publisher key can never vouch for an `entangle` release.
pub fn release_keyring_path() -> PathBuf {
    entangle_dir().join("release-keyring.toml")
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

/// The `[security] max_tier_allowed` ceiling from `~/.entangle/config.toml`.
pub fn max_tier_allowed() -> anyhow::Result<entangle_types::tier::Tier> {
    let cfg = load(&config_path())?;
    entangle_types::tier::Tier::try_from(cfg.security.max_tier_allowed).map_err(|e| {
        anyhow::anyhow!(
            "invalid [security] max_tier_allowed in {}: {e}",
            config_path().display()
        )
    })
}

/// Kernel settings for the CLI's in-process (`--allow-local`) kernel.
///
/// Honours the same `[security]` keys as the daemon — the tier ceiling
/// (`max_tier_allowed = 4` disables tier-5 plugins) and the native-plugin
/// sandbox opt-out, and the `deny_capabilities` list — so a local load is
/// never more permissive than the daemon would be. Native plugin storage lives in `~/.entangle/data`, staged
/// binaries in `~/.entangle/native`.
pub fn kernel_config() -> anyhow::Result<entangle_runtime::KernelConfig> {
    let cfg = load(&config_path())?;
    let dir = entangle_dir();
    let denied_capabilities = cfg
        .security
        .deny_capabilities
        .iter()
        .map(|p| p.parse::<entangle_runtime::CapabilityPattern>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            anyhow::anyhow!(
                "[security] deny_capabilities in {}: {e}",
                config_path().display()
            )
        })?;
    Ok(entangle_runtime::KernelConfig {
        max_tier_allowed: max_tier_allowed()?,
        denied_capabilities,
        disabled_plugins: cfg.plugins.disabled.clone(),
        aot_cache: runtime_aot_cache(&config_path())
            .then(|| entangle_runtime::AotCacheConfig::new(dir.join("aot"))),
        native: entangle_runtime::NativeConfig {
            allow_unsandboxed: cfg.security.allow_unsandboxed_native,
            data_dir: Some(dir.join("data")),
            staging_dir: Some(dir.join("native")),
            ..entangle_runtime::NativeConfig::default()
        },
        ..entangle_runtime::KernelConfig::default()
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_local_kernel_reads_only_runtime_aot_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        assert!(runtime_aot_cache(&path), "absent file: on");
        std::fs::write(&path, "[runtime]\nbus_capacity = 64\n").unwrap();
        assert!(runtime_aot_cache(&path), "absent key: on");
        std::fs::write(&path, "[runtime]\naot_cache = false\n").unwrap();
        assert!(!runtime_aot_cache(&path));
        // The CLI's own schema ignores the daemon's section.
        assert!(load(&path).is_ok());
    }
}
