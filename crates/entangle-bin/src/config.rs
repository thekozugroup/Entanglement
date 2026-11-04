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
    /// Cross-node scheduler settings (daemon-only section).
    ///
    /// Inert unless `[mesh] transports` contains `"iroh"`, so a config
    /// written by an older CLI — which omits this section entirely — leaves
    /// the daemon single-machine, exactly as before.
    pub scheduler: SchedulerConfig,
}

/// Cross-node scheduler settings (daemon-only).
///
/// This section only matters when `"iroh"` appears in `[mesh] transports`.
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
    /// port.
    pub bind: String,
    /// Long addresses (`<pubkey-hex>@host:port`) of peers this node may
    /// dispatch work to.
    ///
    /// An entry is used only if that peer is *also* trusted in the peer
    /// store, so listing an address here does not by itself grant anything.
    pub peers: Vec<String>,
    /// Whether to allow relay fallback when hole-punching fails. Disable for
    /// a LAN-only deployment that must never touch third-party relays.
    pub relay: bool,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:0".to_owned(),
            peers: Vec::new(),
            relay: true,
        }
    }
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
    /// `[mesh.tailscale]` — daemon-side settings for the `mesh.tailscale`
    /// transport (spec §6.1.1). Inert unless `enabled = true` **and**
    /// `transports` contains `"tailscale"`.
    pub tailscale: TailscaleSection,
}

/// `[mesh.tailscale]` section.
///
/// ```toml
/// [mesh]
/// transports = ["tailscale"]
///
/// [mesh.tailscale]
/// enabled = true
/// port = 41643
/// acl-mode = "entangle-on-top"   # or "trust-tailnet"
/// tailscale-cli = ""             # empty = look up `tailscale` on $PATH
/// # bind-ip = "100.101.102.103"  # omitted = all interfaces
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct TailscaleSection {
    /// Opt-in switch: the daemon never joins or uses a tailnet unasked.
    pub enabled: bool,
    /// TCP port for Entanglement traffic over the tailnet.
    pub port: u16,
    /// `"entangle-on-top"` (default) or `"trust-tailnet"` (alias
    /// `"tailscale-only"`). Validated when the file is loaded.
    #[serde(deserialize_with = "de_acl_mode")]
    pub acl_mode: String,
    /// Path to the `tailscale` CLI; empty = `$PATH`.
    pub tailscale_cli: String,
    /// Local address for the listener (e.g. this node's tailnet IP). Omitted
    /// = all interfaces. Either way only tailnet source addresses
    /// (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`) are served.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_ip: Option<std::net::IpAddr>,
}

/// Accept only spellings `entangle_mesh_tailscale::AclMode` understands, so a
/// typo fails the load (as an unknown key does) instead of surfacing later as
/// a transport that silently never started.
fn de_acl_mode<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let s = String::deserialize(d)?;
    s.parse::<entangle_mesh_tailscale::AclMode>()
        .map_err(|e| serde::de::Error::custom(format!("acl-mode: {e}")))?;
    Ok(s)
}

impl Default for TailscaleSection {
    fn default() -> Self {
        Self {
            enabled: false,
            port: entangle_mesh_tailscale::DEFAULT_PORT,
            acl_mode: "entangle-on-top".to_owned(),
            tailscale_cli: String::new(),
            bind_ip: None,
        }
    }
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
    ///
    /// This is the "one config line" that disables native plugins globally:
    /// `max_tier_allowed = 4` refuses every tier-5 plugin, `3` refuses every
    /// native (tier 4–5) plugin (spec §9.4.1).
    pub max_tier_allowed: Tier,
    /// Run native (tier 4–5) plugins even on a host with **no** OS sandbox
    /// primitive (no Landlock, bubblewrap, or Seatbelt). Default `false`:
    /// such a plugin is refused with `ENTANGLE-E0700`. Has no effect on a host
    /// that has a primitive — the sandbox is then always engaged.
    pub allow_unsandboxed_native: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_tier_allowed: Tier::Native,
            allow_unsandboxed_native: false,
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

/// Build the runtime [`KernelConfig`](entangle_runtime::KernelConfig) the
/// daemon uses from a parsed config and the config directory (`~/.entangle`).
///
/// Native plugins store their scopes under `<config_dir>/data` and are staged
/// for execution under `<config_dir>/native` (both created on demand, 0700).
pub fn kernel_config(cfg: &Config, config_dir: &std::path::Path) -> entangle_runtime::KernelConfig {
    entangle_runtime::KernelConfig {
        max_tier_allowed: cfg.security.max_tier_allowed,
        multi_node: cfg.mesh.multi_node,
        bus_capacity: cfg.runtime.bus_capacity,
        native: entangle_runtime::NativeConfig {
            allow_unsandboxed: cfg.security.allow_unsandboxed_native,
            data_dir: Some(config_dir.join("data")),
            staging_dir: Some(config_dir.join("native")),
            ..entangle_runtime::NativeConfig::default()
        },
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
    fn unsandboxed_native_opt_out_is_off_unless_set() {
        let cfg: Config = toml::from_str("").unwrap();
        assert!(!cfg.security.allow_unsandboxed_native);
        let cfg: Config = toml::from_str("[security]\nallow_unsandboxed_native = true\n").unwrap();
        assert!(cfg.security.allow_unsandboxed_native);
        let k = kernel_config(&cfg, std::path::Path::new("/home/u/.entangle"));
        assert!(k.native.allow_unsandboxed);
        assert_eq!(
            k.native.data_dir.as_deref(),
            Some(std::path::Path::new("/home/u/.entangle/data"))
        );
    }

    /// README: tier-5 "can be disabled globally with one config line".
    #[test]
    fn one_line_disables_tier_five() {
        let cfg: Config = toml::from_str("[security]\nmax_tier_allowed = 4\n").unwrap();
        let k = kernel_config(&cfg, std::path::Path::new("/x"));
        assert_eq!(k.max_tier_allowed, Tier::Privileged);
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
    fn tailscale_section_parses_with_kebab_keys_and_defaults_off() {
        let cfg: Config = toml::from_str("").unwrap();
        assert!(!cfg.mesh.tailscale.enabled);
        assert_eq!(cfg.mesh.tailscale.acl_mode, "entangle-on-top");
        let cfg: Config = toml::from_str(
            "[mesh]\ntransports=[\"tailscale\"]\n[mesh.tailscale]\nenabled=true\nport=9\nacl-mode=\"trust-tailnet\"\ntailscale-cli=\"/x/ts\"\n",
        )
        .unwrap();
        assert!(cfg.mesh.tailscale.enabled);
        assert_eq!(cfg.mesh.tailscale.port, 9);
        assert_eq!(cfg.mesh.tailscale.tailscale_cli, "/x/ts");
        assert!(toml::from_str::<Config>("[mesh.tailscale]\nbogus=1\n").is_err());
    }

    #[test]
    fn tailscale_acl_mode_is_validated_when_the_file_is_loaded() {
        // A typo must stop the daemon at load time (like every other key),
        // not leave it running without the transport the operator enabled.
        for bad in ["entangle_on_top", "trust-tailnet ", "open", ""] {
            let raw = format!("[mesh.tailscale]\nenabled = true\nacl-mode = {bad:?}\n");
            let err = toml::from_str::<Config>(&raw).expect_err(bad);
            assert!(err.to_string().contains("acl-mode"), "{bad:?}: {err}");
        }
        for good in ["entangle-on-top", "trust-tailnet", "tailscale-only"] {
            let raw = format!("[mesh.tailscale]\nacl-mode = {good:?}\n");
            assert!(toml::from_str::<Config>(&raw).is_ok(), "{good}");
        }
    }

    #[test]
    fn tailscale_bind_ip_is_configurable_and_validated() {
        let cfg: Config =
            toml::from_str("[mesh.tailscale]\nbind-ip = \"100.101.102.103\"\n").unwrap();
        let built =
            crate::tailscale::build_config(&cfg.mesh, entangle_peers::PeerStore::new()).unwrap();
        assert_eq!(
            built.bind_ip,
            "100.101.102.103".parse::<std::net::IpAddr>().unwrap()
        );
        // Not an address: refused when the file is loaded, not at runtime.
        assert!(toml::from_str::<Config>("[mesh.tailscale]\nbind-ip = \"tailnet\"\n").is_err());
        // Omitted: all interfaces (inbound sources are still filtered).
        let cfg: Config = toml::from_str("").unwrap();
        let built =
            crate::tailscale::build_config(&cfg.mesh, entangle_peers::PeerStore::new()).unwrap();
        assert!(built.bind_ip.is_unspecified());
    }

    #[test]
    fn load_config_missing_file_yields_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = load_config(&dir.path().join("config.toml")).unwrap();
        assert_eq!(cfg.security.max_tier_allowed, Tier::Native);
        assert!(!cfg.mesh.multi_node);
    }
}
