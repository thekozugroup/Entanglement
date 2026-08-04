//! Daemon configuration — mirrors the CLI's `~/.entangle/config.toml` schema.
//!
//! The `[mesh]` and `[security]` sections MUST stay field-for-field compatible
//! with `entangle-cli`'s `Config` (`crates/entangle-cli/src/config.rs`): the
//! CLI writes the file, the daemon reads it. The round-trip test at the bottom
//! of this file pins the shared shape so the two schemas cannot silently
//! drift. The `[runtime]` section is daemon-only tuning.
//!
//! Every section uses `deny_unknown_fields`, so a stale or typo'd key is a
//! loud startup error instead of a silently ignored setting.

use entangle_types::tier::Tier;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level daemon configuration (deserialized from `~/.entangle/config.toml`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Runtime-specific tuning knobs (daemon-only section).
    pub runtime: RuntimeConfig,
    /// Mesh transport configuration (shared with the CLI schema).
    pub mesh: MeshConfig,
    /// Security policy (shared with the CLI schema).
    pub security: SecurityConfig,
}

/// Mesh-layer configuration.
///
/// Mirrors `entangle-cli`'s `MeshConfig` exactly.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MeshConfig {
    /// Active transport backends.  Phase 1 supports `"local"` (mDNS).
    /// Example in `config.toml`: `transports = ["local"]`
    pub transports: Vec<String>,
    /// When `true` the daemon requires at least one trusted peer before
    /// starting (spec §11 #16, enforced via ENTANGLE-E0050 at startup).
    pub multi_node: bool,
}

/// Security policy configuration.
///
/// Mirrors `entangle-cli`'s `SecurityConfig` exactly. The CLI stores the tier
/// as a bare `u8`; [`Tier`] serializes to/from the same integer wire form
/// (1..=5), so the two representations are interchangeable on disk while the
/// daemon gets range validation for free at parse time.
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
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self { bus_capacity: 1024 }
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

/// Resolve the default socket path.
///
/// Preference order:
/// 1. `~/.entangle/sock` when a home directory exists (spec §9.1);
/// 2. `$XDG_RUNTIME_DIR/entangle/sock` — a per-user, mode-0700 runtime dir;
/// 3. hard error. Never a predictable world-writable location like `/tmp`,
///    where another local user could pre-create or squat the path.
pub fn default_socket_path() -> anyhow::Result<PathBuf> {
    if let Some(base) = directories::BaseDirs::new() {
        return Ok(base.home_dir().join(".entangle").join("sock"));
    }
    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        let dir = PathBuf::from(runtime_dir);
        if dir.is_absolute() {
            return Ok(dir.join("entangle").join("sock"));
        }
    }
    anyhow::bail!(
        "cannot resolve a private socket path: no home directory and no absolute \
         $XDG_RUNTIME_DIR (refusing to fall back to world-writable /tmp)"
    )
}

/// Resolve the default config directory: `~/.entangle/`.
///
/// Hard-errors when no home directory can be determined — the directory holds
/// the identity private key, so falling back to a predictable world-writable
/// path such as `/tmp` is never acceptable.
pub fn default_config_dir() -> anyhow::Result<PathBuf> {
    if let Some(base) = directories::BaseDirs::new() {
        return Ok(base.home_dir().join(".entangle"));
    }
    anyhow::bail!(
        "cannot resolve the config directory: no home directory available — set $HOME \
         (refusing to fall back to world-writable /tmp)"
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-for-byte what `entangle-cli`'s `config::save` writes
    /// (`toml::to_string_pretty` of its `Config`). If this fixture stops
    /// parsing, the CLI and daemon schemas have drifted.
    const CLI_WRITTEN_CONFIG: &str = r#"[mesh]
transports = ["local"]
multi_node = true

[security]
max_tier_allowed = 2
"#;

    #[test]
    fn cli_written_config_round_trips_with_all_fields_preserved() {
        let cfg: Config = toml::from_str(CLI_WRITTEN_CONFIG).expect("CLI-written config parses");
        assert_eq!(cfg.mesh.transports, vec!["local".to_owned()]);
        assert!(cfg.mesh.multi_node);
        assert_eq!(cfg.security.max_tier_allowed, Tier::Sandboxed);

        // Daemon-side serialize → reparse: every field survives the round trip.
        let out = toml::to_string_pretty(&cfg).expect("serialize");
        let reparsed: Config = toml::from_str(&out).expect("reparse");
        assert_eq!(reparsed.mesh.transports, cfg.mesh.transports);
        assert_eq!(reparsed.mesh.multi_node, cfg.mesh.multi_node);
        assert_eq!(
            reparsed.security.max_tier_allowed,
            cfg.security.max_tier_allowed
        );
        assert_eq!(reparsed.runtime.bus_capacity, cfg.runtime.bus_capacity);
    }

    #[test]
    fn empty_config_uses_defaults() {
        let cfg: Config = toml::from_str("").expect("empty config parses");
        assert_eq!(cfg.security.max_tier_allowed, Tier::Native);
        assert!(!cfg.mesh.multi_node);
        assert!(cfg.mesh.transports.is_empty());
        assert_eq!(cfg.runtime.bus_capacity, 1024);
    }

    #[test]
    fn out_of_range_tier_is_rejected_at_parse_time() {
        assert!(toml::from_str::<Config>("[security]\nmax_tier_allowed = 6\n").is_err());
        assert!(toml::from_str::<Config>("[security]\nmax_tier_allowed = 0\n").is_err());
    }

    #[test]
    fn unknown_field_is_a_hard_error() {
        // deny_unknown_fields: a typo'd key fails loudly instead of being
        // silently dropped (which would leave the permissive default active).
        assert!(toml::from_str::<Config>("[security]\nmax_teir_allowed = 2\n").is_err());
        // The old (pre-WP5) daemon-only knob locations also fail loudly.
        assert!(toml::from_str::<Config>("[runtime]\nmulti_node = true\n").is_err());
        assert!(toml::from_str::<Config>("[runtime]\nmax_tier = \"native\"\n").is_err());
    }

    #[test]
    fn load_config_missing_file_yields_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = load_config(&dir.path().join("config.toml")).unwrap();
        assert_eq!(cfg.security.max_tier_allowed, Tier::Native);
        assert!(!cfg.mesh.multi_node);
    }
}
