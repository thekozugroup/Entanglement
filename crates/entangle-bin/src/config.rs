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
    /// `[node]` — this device (see [`NodeSection`]).
    pub node: NodeSection,
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
    /// `[wrappers]` — written by `entangle wrapper enable|disable`; the
    /// daemon ignores it (it is the shell shim's opt-in record).
    pub wrappers: WrappersSection,
    /// `[plugins]` — operator state about plugins (see [`PluginsSection`]).
    pub plugins: PluginsSection,
    /// Prometheus `/metrics` endpoint (daemon-only section; off by default).
    pub metrics: MetricsSection,
    /// Tracing export (daemon-only section; off by default).
    pub telemetry: TelemetrySection,
    /// Trust policy for remote requests (daemon-only section).
    pub trust: TrustSection,
}

/// `[node]` — this device (spec §9.4).
///
/// ```toml
/// [node]
/// label = "alice-laptop"   # shown to peers when pairing and in mDNS
/// ```
///
/// `label` is the human-readable device label `entangle init` asks for. The
/// daemon advertises it (mDNS, `entangle diag mesh`) and `entangle pair`
/// shows it to the other device (spec §6.3 step 2); absent, both fall back
/// to the host name. It is at most [`MAX_LABEL_LEN`] bytes, not blank and
/// without control characters, validated when the file is loaded.
///
/// *Deviation (spec §9.4):* the spec's `data_dir` and `identity` keys are
/// not supported — every command and the daemon resolve their files under
/// `~/.entangle` directly — and fail the load with a message saying so,
/// rather than as an unknown key.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct NodeSection {
    /// Human-readable device label.
    #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "de_label")]
    pub label: Option<String>,
    /// Not supported (spec §9.4 deviation); present only to explain so.
    #[serde(
        skip_serializing,
        deserialize_with = "de_unsupported_data_dir",
        rename = "data_dir"
    )]
    pub data_dir: Option<()>,
    /// Not supported (spec §9.4 deviation); present only to explain so.
    #[serde(
        skip_serializing,
        deserialize_with = "de_unsupported_identity",
        rename = "identity"
    )]
    pub identity: Option<()>,
}

/// Longest accepted `[node] label`, in bytes (what pairing accepts from the
/// other device, too).
pub const MAX_LABEL_LEN: usize = 64;

/// Check a device label: not blank, at most [`MAX_LABEL_LEN`] bytes, no
/// control characters.
pub fn check_label(label: &str) -> Result<(), String> {
    if label.trim().is_empty() {
        return Err("[node] label must not be blank".into());
    }
    if label.len() > MAX_LABEL_LEN {
        return Err(format!(
            "[node] label is {} bytes; at most {MAX_LABEL_LEN} are allowed",
            label.len()
        ));
    }
    if label.chars().any(char::is_control) {
        return Err("[node] label must not contain control characters".into());
    }
    Ok(())
}

fn de_label<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    let s = String::deserialize(d)?;
    check_label(&s).map_err(serde::de::Error::custom)?;
    Ok(Some(s))
}

fn unsupported_node_key<'de, D: serde::Deserializer<'de>>(
    d: D,
    key: &str,
) -> Result<Option<()>, D::Error> {
    serde::de::IgnoredAny::deserialize(d)?;
    Err(serde::de::Error::custom(format!(
        "[node] {key} is not supported: Entanglement keeps its files in ~/.entangle \
         (set HOME to relocate them); remove the key"
    )))
}

fn de_unsupported_data_dir<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<()>, D::Error> {
    unsupported_node_key(d, "data_dir")
}

fn de_unsupported_identity<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<()>, D::Error> {
    unsupported_node_key(d, "identity")
}

impl Config {
    /// The configured device label, if any.
    pub fn node_label(&self) -> Option<&str> {
        self.node.label.as_deref()
    }

    /// The checks the daemon makes on a parsed file before it starts
    /// anything (beyond those `toml::from_str` already makes): the OTLP
    /// exporter settings, the metrics listen address (when enabled), the
    /// transport routing policy, and the `mesh.tailscale` settings.
    ///
    /// `entangle config set` runs this on the edited file before writing it,
    /// so it never writes a file the daemon would refuse at startup.
    pub fn validate(&self) -> anyhow::Result<()> {
        use anyhow::Context as _;
        self.telemetry
            .otel_config()
            .context("[telemetry.otlp] is invalid")?;
        if self.metrics.enabled {
            crate::metrics_server::resolve_listen(&self.metrics).context("[metrics] is invalid")?;
        }
        self.mesh
            .route_policy()
            .context("[mesh] preferred / [mesh.overrides]")?;
        crate::tailscale::build_config(&self.mesh, entangle_peers::PeerStore::new())?;
        Ok(())
    }
}

/// `[trust]` — how this node authorises work peers send it.
///
/// ```toml
/// [trust]
/// require_capability_tokens = true   # default; `false` only while migrating
/// ```
///
/// With `true` (the default, fail closed), every remote task frame and
/// stream `Open` must carry a valid per-request capability token (spec
/// §6.1.1, §6.3 step 4) on top of passing the peer allowlist; a request
/// without one is refused with `ENTANGLE-E0450`, which tells the sender to
/// re-pair. With `false`, a request **without** a token from an allowlisted
/// peer is accepted — the daemon warns at startup and counts each one
/// (`entangle_remote_capability_checks_total{outcome="tokenless_accepted"}`)
/// — so peers paired before tokens existed keep working until they re-pair;
/// a request that **does** carry a token is still fully verified.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct TrustSection {
    /// Refuse remote requests that carry no capability token.
    pub require_capability_tokens: bool,
}

impl Default for TrustSection {
    fn default() -> Self {
        Self {
            require_capability_tokens: true,
        }
    }
}

/// `[wrappers]` section (CLI-owned; accepted so the daemon still starts).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WrappersSection {
    /// Opt-in record for the shell shim (spec §8.3 item 2).
    pub install: bool,
}

/// `[plugins]` section.
///
/// `disabled` is written by the max-tier lowering workflow (spec §9.4.1
/// step 4) and by `entangle plugins disable`. The kernel refuses to load a
/// listed id (`ENTANGLE-E0759`), and so does the submitter's metric registry
/// for a metric package; the daemon re-reads this list before each
/// `plugins/load` and metric load, so `entangle plugins enable <id>` takes
/// effect without a restart.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PluginsSection {
    /// Plugin ids unloaded and disabled by a tier-ceiling lowering.
    pub disabled: Vec<String>,
}

/// `[metrics]` — the Prometheus scrape endpoint (spec §9.6).
///
/// ```toml
/// [metrics]
/// enabled = true
/// listen = "127.0.0.1:9464"
/// # allow_non_loopback = true   # required for any non-loopback address
/// ```
///
/// The endpoint is unauthenticated, so it is loopback-only unless the
/// operator explicitly opts in with `allow_non_loopback = true` (and then
/// should firewall it). `listen` must be an IP literal and port.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsSection {
    /// Serve `GET /metrics`. Off by default.
    pub enabled: bool,
    /// `ip:port` to listen on.
    pub listen: String,
    /// Permit a non-loopback `listen` address.
    pub allow_non_loopback: bool,
}

impl Default for MetricsSection {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: crate::metrics_server::DEFAULT_LISTEN.to_owned(),
            allow_non_loopback: false,
        }
    }
}

/// `[telemetry]` — tracing export.
///
/// ```toml
/// [telemetry.otlp]
/// enabled = true
/// endpoint = "http://localhost:4318"   # OTLP/HTTP (JSON); 4317 is gRPC
/// service_name = "entangled"
/// ```
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetrySection {
    /// OTLP/HTTP trace exporter.
    pub otlp: OtlpSection,
}

/// `[telemetry.otlp]` — see [`TelemetrySection`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct OtlpSection {
    /// Export spans. Off by default.
    pub enabled: bool,
    /// OTLP/HTTP base endpoint; spans go to `<endpoint>/v1/traces`.
    pub endpoint: String,
    /// `service.name` resource attribute.
    pub service_name: String,
}

impl Default for OtlpSection {
    fn default() -> Self {
        let d = entangle_observability::OtelConfig::default();
        Self {
            enabled: false,
            endpoint: d.endpoint,
            service_name: d.service_name,
        }
    }
}

impl TelemetrySection {
    /// The exporter configuration, or `None` when export is off. Validates
    /// the endpoint and service name (`ENTANGLE-E0651`/`E0652`) so a typo
    /// stops the daemon at startup.
    pub fn otel_config(
        &self,
    ) -> Result<Option<entangle_observability::OtelConfig>, entangle_observability::OtelError> {
        if !self.otlp.enabled {
            return Ok(None);
        }
        let cfg = entangle_observability::OtelConfig {
            endpoint: self.otlp.endpoint.clone(),
            service_name: self.otlp.service_name.clone(),
            ..Default::default()
        };
        entangle_observability::otel::validate(&cfg)?;
        Ok(Some(cfg))
    }
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
/// spot_check_probability = 0.01     # Layer-2 spot-checks (spec §7.5); 0 disables
/// spot_check_max_concurrent = 4
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
    /// Layer-2 spot-checks (spec §7.5): the probability, in `[0, 1]`, that an
    /// accepted `Deterministic` or `SemanticEquivalent` task is re-run on an
    /// executor that produced none of its replicas and compared with the
    /// accepted output. Default `0.01` (the spec's 1 %); `0` disables them,
    /// `1` checks every eligible task. Validated when the file is loaded.
    #[serde(deserialize_with = "de_probability")]
    pub spot_check_probability: f64,
    /// Most spot-checks running at once, from 1 to
    /// `entangle_scheduler::spot_check::MAX_CONCURRENT_LIMIT` (1024); a
    /// sampled task that finds them all busy is skipped and counted, never
    /// queued. Validated when the file is loaded.
    #[serde(deserialize_with = "de_concurrency")]
    pub spot_check_max_concurrent: usize,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:0".to_owned(),
            peers: Vec::new(),
            relay: true,
            spot_check_probability: entangle_scheduler::spot_check::DEFAULT_PROBABILITY,
            spot_check_max_concurrent: entangle_scheduler::spot_check::DEFAULT_MAX_CONCURRENT,
        }
    }
}

impl SchedulerConfig {
    /// The dispatcher's spot-check settings.
    pub fn spot_checks(&self) -> entangle_scheduler::SpotCheckConfig {
        entangle_scheduler::SpotCheckConfig {
            probability: self.spot_check_probability,
            max_concurrent: self.spot_check_max_concurrent,
        }
    }
}

fn de_probability<'de, D: serde::Deserializer<'de>>(d: D) -> Result<f64, D::Error> {
    let p = f64::deserialize(d)?;
    if !(0.0..=1.0).contains(&p) {
        return Err(serde::de::Error::custom(format!(
            "[scheduler] spot_check_probability must be between 0 and 1, got {p}"
        )));
    }
    Ok(p)
}

fn de_concurrency<'de, D: serde::Deserializer<'de>>(d: D) -> Result<usize, D::Error> {
    let n = usize::deserialize(d)?;
    if n == 0 {
        return Err(serde::de::Error::custom(
            "[scheduler] spot_check_max_concurrent must be at least 1 (set \
             spot_check_probability = 0 to disable spot-checks)",
        ));
    }
    let limit = entangle_scheduler::spot_check::MAX_CONCURRENT_LIMIT;
    if n > limit {
        return Err(serde::de::Error::custom(format!(
            "[scheduler] spot_check_max_concurrent must be at most {limit}, got {n} (each \
             running spot-check holds a re-run and, for semantic-equivalent, the accepted \
             output)"
        )));
    }
    Ok(n)
}

/// Mesh-layer configuration.
///
/// `transports` and `multi_node` mirror `entangle-cli`'s `MeshConfig`
/// exactly; `preferred`, `[mesh.overrides]` and `[mesh.tailscale]` are
/// daemon-only (the CLI ignores them when it reads the file and keeps them
/// when it edits it).
///
/// ```toml
/// [mesh]
/// transports = ["local", "tailscale", "iroh"]
/// preferred = "tailscale"        # tried first for every peer (spec §6.1)
///
/// [mesh.overrides]               # per peer (peer id hex): exactly these, in order
/// "7a21c0de7a21c0de7a21c0de7a21c0de" = "iroh"
/// "0b5e55ed0b5e55ed0b5e55ed0b5e55ed" = ["tailscale", "iroh"]
/// ```
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MeshConfig {
    /// Active transport backends: `"local"` (mDNS), `"iroh"`, `"tailscale"`.
    /// Example in `config.toml`: `transports = ["local"]`
    pub transports: Vec<String>,
    /// When `true` the daemon requires at least one trusted peer before
    /// starting (spec §11 #16, enforced via ENTANGLE-E0050 at startup).
    pub multi_node: bool,
    /// `[mesh] preferred` — the transport tried first for every peer
    /// without an override (`"local"`, `"tailscale"` or `"iroh"`); the
    /// others stay as fallbacks in the spec §6.1 order. Validated when the
    /// file is loaded (`ENTANGLE-E0434`).
    #[serde(
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de_preferred"
    )]
    pub preferred: Option<String>,
    /// `[mesh.overrides]` — per-peer transport choice, keyed by peer id
    /// (hex): one transport forces it, a list gives the exact order. Peers
    /// listed here do not fall back to transports their entry omits.
    /// Validated when the file is loaded (`ENTANGLE-E0434`/`E0435`).
    #[serde(
        skip_serializing_if = "std::collections::BTreeMap::is_empty",
        deserialize_with = "de_overrides"
    )]
    pub overrides: std::collections::BTreeMap<String, TransportOverride>,
    /// `[mesh.tailscale]` — daemon-side settings for the `mesh.tailscale`
    /// transport (spec §6.1.1). Inert unless `enabled = true` **and**
    /// `transports` contains `"tailscale"`.
    pub tailscale: TailscaleSection,
}

/// One `[mesh.overrides]` entry: a transport, or an ordered list of them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TransportOverride {
    /// `"<peer>" = "iroh"`: only this transport.
    One(String),
    /// `"<peer>" = ["tailscale", "iroh"]`: these, in this order.
    Order(Vec<String>),
}

impl TransportOverride {
    /// The transport names, in order.
    pub fn names(&self) -> Vec<&str> {
        match self {
            Self::One(s) => vec![s.as_str()],
            Self::Order(v) => v.iter().map(String::as_str).collect(),
        }
    }
}

fn de_preferred<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    let s = String::deserialize(d)?;
    s.parse::<entangle_scheduler::TransportKind>()
        .map_err(|e| serde::de::Error::custom(format!("[mesh] preferred: {e}")))?;
    Ok(Some(s))
}

fn de_overrides<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<std::collections::BTreeMap<String, TransportOverride>, D::Error> {
    let map = std::collections::BTreeMap::<String, TransportOverride>::deserialize(d)?;
    for (key, value) in &map {
        parse_override(key, value)
            .map_err(|e| serde::de::Error::custom(format!("[mesh.overrides]: {e}")))?;
    }
    Ok(map)
}

/// Parse one `[mesh.overrides]` entry (the scheduler library's validation,
/// shared with `entangle compute stream`).
fn parse_override(
    key: &str,
    value: &TransportOverride,
) -> Result<
    (
        entangle_types::peer_id::PeerId,
        Vec<entangle_scheduler::TransportKind>,
    ),
    entangle_scheduler::RouteError,
> {
    entangle_scheduler::RoutePolicy::parse_override(key, &value.names())
}

impl MeshConfig {
    /// The routing policy `preferred` and `[mesh.overrides]` describe
    /// (spec §6.1 order otherwise).
    pub fn route_policy(
        &self,
    ) -> Result<entangle_scheduler::RoutePolicy, entangle_scheduler::RouteError> {
        let preferred = self
            .preferred
            .as_deref()
            .map(str::parse::<entangle_scheduler::TransportKind>)
            .transpose()?;
        let mut policy = entangle_scheduler::RoutePolicy::new().with_preferred(preferred);
        for (key, value) in &self.overrides {
            let (peer, kinds) = parse_override(key, value)?;
            policy = policy.with_override(peer, kinds);
        }
        Ok(policy)
    }
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
    /// Capabilities the broker never grants to any plugin, whatever its
    /// manifest declares (spec §4.5): exact keys (`net.wan`,
    /// `storage.share.photos`), family prefixes (`net.*`, `storage.share.*`)
    /// or `*`. A plugin that declares a denied capability still loads,
    /// without it; the denial is audited and shown by `entangle perms list`.
    /// An invalid pattern is a startup error (`ENTANGLE-E0126`).
    pub deny_capabilities: Vec<entangle_broker::CapabilityPattern>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_tier_allowed: Tier::Native,
            allow_unsandboxed_native: false,
            deny_capabilities: Vec::new(),
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
        denied_capabilities: cfg.security.deny_capabilities.clone(),
        disabled_plugins: cfg.plugins.disabled.clone(),
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
    fn spot_check_settings_default_to_the_spec_rate_and_are_validated() {
        let cfg: Config = toml::from_str("").unwrap();
        let spot = cfg.scheduler.spot_checks();
        assert_eq!(spot.probability, 0.01, "spec §7.5: 1 % of accepted tasks");
        assert_eq!(
            spot.max_concurrent,
            entangle_scheduler::spot_check::DEFAULT_MAX_CONCURRENT
        );
        let cfg: Config = toml::from_str(
            "[scheduler]\nspot_check_probability = 1\nspot_check_max_concurrent = 2\n",
        )
        .unwrap();
        assert_eq!(
            (
                cfg.scheduler.spot_check_probability,
                cfg.scheduler.spot_check_max_concurrent
            ),
            (1.0, 2)
        );
        let off: Config = toml::from_str("[scheduler]\nspot_check_probability = 0.0\n").unwrap();
        assert_eq!(off.scheduler.spot_checks().probability, 0.0);
        for bad in [
            "spot_check_probability = 1.5",
            "spot_check_probability = -0.1",
            "spot_check_probability = nan",
            "spot_check_max_concurrent = 0",
        ] {
            let err = toml::from_str::<Config>(&format!("[scheduler]\n{bad}\n")).expect_err(bad);
            assert!(err.to_string().contains("spot_check"), "{bad}: {err}");
        }
        // A round trip keeps the settings.
        let again: Config = toml::from_str(&toml::to_string_pretty(&cfg).unwrap()).unwrap();
        assert_eq!(again.scheduler.spot_check_max_concurrent, 2);
    }

    /// A concurrency the dispatcher cannot build (tokio's semaphore panics
    /// above `usize::MAX >> 3` permits) is refused when the file is loaded,
    /// not by a panic at daemon start-up; the documented bound is accepted.
    #[test]
    fn spot_check_concurrency_above_the_bound_fails_the_load() {
        let limit = entangle_scheduler::spot_check::MAX_CONCURRENT_LIMIT;
        for too_many in [
            (limit + 1).to_string(),
            (1u64 << 61).to_string(),
            i64::MAX.to_string(),
        ] {
            let text = format!("[scheduler]\nspot_check_max_concurrent = {too_many}\n");
            let err = toml::from_str::<Config>(&text).expect_err(&too_many);
            assert!(
                err.to_string().contains("spot_check_max_concurrent"),
                "{too_many}: {err}"
            );
        }
        let cfg: Config = toml::from_str(&format!(
            "[scheduler]\nspot_check_max_concurrent = {limit}\n"
        ))
        .unwrap();
        assert_eq!(cfg.scheduler.spot_check_max_concurrent, limit);
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
    fn preferred_and_per_peer_overrides_parse_into_a_route_policy() {
        use entangle_scheduler::TransportKind as K;
        let a = "7a21c0de7a21c0de7a21c0de7a21c0de";
        let b = "0b5e55ed0b5e55ed0b5e55ed0b5e55ed";
        let raw = format!(
            "[mesh]\ntransports = [\"local\", \"tailscale\", \"iroh\"]\npreferred = \"iroh\"\n\
             [mesh.overrides]\n\"{a}\" = \"tailscale\"\n\"{b}\" = [\"tailscale\", \"local\"]\n"
        );
        let cfg: Config = toml::from_str(&raw).unwrap();
        let policy = cfg.mesh.route_policy().unwrap();
        let id = |h: &str| entangle_types::peer_id::PeerId::from_hex(h).unwrap();
        assert_eq!(policy.order_for(&id(a)), [K::Tailscale]);
        assert_eq!(policy.order_for(&id(b)), [K::Tailscale, K::Local]);
        let other = entangle_types::peer_id::PeerId::from_public_key_bytes(&[1; 32]);
        assert_eq!(policy.order_for(&other), [K::Iroh, K::Local, K::Tailscale]);
        // Round trip keeps both.
        let again: Config = toml::from_str(&toml::to_string_pretty(&cfg).unwrap()).unwrap();
        assert_eq!(again.mesh.preferred.as_deref(), Some("iroh"));
        assert_eq!(again.mesh.overrides, cfg.mesh.overrides);
        // Absent: the spec order, and nothing new in what the daemon writes.
        let plain: Config = toml::from_str("[mesh]\ntransports = [\"iroh\"]\n").unwrap();
        assert_eq!(
            plain.mesh.route_policy().unwrap().order_for(&other),
            [K::Local, K::Tailscale, K::Iroh]
        );
        let written = toml::to_string_pretty(&plain).unwrap();
        assert!(
            !written.contains("preferred") && !written.contains("overrides"),
            "{written}"
        );
    }

    #[test]
    fn bad_transport_choices_fail_when_the_file_is_loaded() {
        let peer = "7a21c0de7a21c0de7a21c0de7a21c0de";
        for (bad, needle) in [
            (
                "[mesh]\npreferred = \"wifi\"\n".to_owned(),
                "ENTANGLE-E0434",
            ),
            (
                format!("[mesh.overrides]\n\"{peer}\" = \"udp\"\n"),
                "ENTANGLE-E0434",
            ),
            (
                format!("[mesh.overrides]\n\"{peer}\" = []\n"),
                "ENTANGLE-E0435",
            ),
            (
                format!("[mesh.overrides]\n\"{peer}\" = [\"iroh\", \"iroh\"]\n"),
                "ENTANGLE-E0435",
            ),
            (
                "[mesh.overrides]\n\"bob\" = \"iroh\"\n".to_owned(),
                "ENTANGLE-E0435",
            ),
        ] {
            let err = toml::from_str::<Config>(&bad).expect_err(&bad);
            assert!(err.to_string().contains(needle), "{bad}: {err}");
        }
    }

    #[test]
    fn cli_owned_wrappers_and_plugins_sections_are_accepted() {
        // `entangle wrapper enable` and the max-tier lowering workflow write
        // these; a daemon that rejected them would refuse to start.
        let cfg: Config =
            toml::from_str("[wrappers]\ninstall = true\n[plugins]\ndisabled = [\"ab/x@0.1.0\"]\n")
                .unwrap();
        assert!(cfg.wrappers.install);
        assert_eq!(cfg.plugins.disabled, vec!["ab/x@0.1.0".to_owned()]);
        let cfg: Config = toml::from_str("").unwrap();
        assert!(!cfg.wrappers.install && cfg.plugins.disabled.is_empty());
        assert!(toml::from_str::<Config>("[wrappers]\nbogus = 1\n").is_err());
    }

    #[test]
    fn metrics_and_telemetry_default_off_and_existing_configs_stay_valid() {
        // The CLI-written fixture has neither section.
        let cfg: Config = toml::from_str(CLI_WRITTEN_CONFIG).unwrap();
        assert!(!cfg.metrics.enabled);
        assert_eq!(cfg.metrics.listen, "127.0.0.1:9464");
        assert!(!cfg.metrics.allow_non_loopback);
        assert!(!cfg.telemetry.otlp.enabled);
        assert_eq!(cfg.telemetry.otlp.endpoint, "http://localhost:4318");
        assert_eq!(cfg.telemetry.otlp.service_name, "entangled");
        assert!(cfg.telemetry.otel_config().unwrap().is_none());
    }

    #[test]
    fn metrics_and_otlp_sections_parse_and_reject_unknown_keys() {
        let cfg: Config = toml::from_str(
            "[metrics]\nenabled = true\nlisten = \"0.0.0.0:9\"\nallow_non_loopback = true\n\
             [telemetry.otlp]\nenabled = true\nendpoint = \"http://c:4318\"\nservice_name = \"n\"\n",
        )
        .unwrap();
        assert!(cfg.metrics.enabled && cfg.metrics.allow_non_loopback);
        let otel = cfg.telemetry.otel_config().unwrap().unwrap();
        assert_eq!(
            (otel.endpoint.as_str(), otel.service_name.as_str()),
            ("http://c:4318", "n")
        );
        assert!(toml::from_str::<Config>("[metrics]\nbogus = 1\n").is_err());
        assert!(toml::from_str::<Config>("[telemetry.otlp]\nbogus = 1\n").is_err());
        // Round trip keeps both sections.
        let again: Config = toml::from_str(&toml::to_string_pretty(&cfg).unwrap()).unwrap();
        assert_eq!(again.metrics, cfg.metrics);
        assert_eq!(again.telemetry, cfg.telemetry);
    }

    #[test]
    fn enabled_otlp_with_a_bad_endpoint_is_an_error_but_disabled_is_not() {
        let bad: Config =
            toml::from_str("[telemetry.otlp]\nenabled = true\nendpoint = \"localhost:4317\"\n")
                .unwrap();
        let err = bad.telemetry.otel_config().unwrap_err();
        assert!(err.to_string().contains("ENTANGLE-E0651"), "{err}");
        let off: Config =
            toml::from_str("[telemetry.otlp]\nenabled = false\nendpoint = \"nonsense\"\n").unwrap();
        assert!(off.telemetry.otel_config().unwrap().is_none());
    }

    #[test]
    fn load_config_missing_file_yields_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = load_config(&dir.path().join("config.toml")).unwrap();
        assert_eq!(cfg.security.max_tier_allowed, Tier::Native);
        assert!(!cfg.mesh.multi_node);
    }
    #[test]
    fn node_label_is_optional_validated_and_round_trips() {
        let cfg: Config = toml::from_str("").unwrap();
        assert_eq!(cfg.node_label(), None);
        let cfg: Config = toml::from_str("[node]\nlabel = \"alice-laptop\"\n").unwrap();
        assert_eq!(cfg.node_label(), Some("alice-laptop"));
        let again: Config = toml::from_str(&toml::to_string_pretty(&cfg).unwrap()).unwrap();
        assert_eq!(again.node, cfg.node);
        let long = "x".repeat(MAX_LABEL_LEN + 1);
        for bad in [
            "\"  \"".to_owned(),
            format!("{long:?}"),
            "\"a\\nb\"".to_owned(),
        ] {
            let err =
                toml::from_str::<Config>(&format!("[node]\nlabel = {bad}\n")).expect_err(&bad);
            assert!(err.to_string().contains("[node] label"), "{bad}: {err}");
        }
        assert!(toml::from_str::<Config>("[node]\nbogus = 1\n").is_err());
    }

    /// Spec §9.4 deviation: `data_dir` / `identity` are refused with a
    /// message that says why, not as an anonymous unknown key.
    #[test]
    fn node_data_dir_and_identity_are_refused_with_an_explanation() {
        for key in ["data_dir", "identity"] {
            let err = toml::from_str::<Config>(&format!("[node]\n{key} = \"/var/lib/entangle\"\n"))
                .expect_err(key);
            let text = err.to_string();
            assert!(
                text.contains(&format!("[node] {key} is not supported")),
                "{text}"
            );
        }
    }

    #[test]
    fn validate_runs_the_daemon_startup_checks() {
        let ok: Config = toml::from_str("[metrics]\nenabled = true\n").unwrap();
        ok.validate().unwrap();
        let bad_listen: Config =
            toml::from_str("[metrics]\nenabled = true\nlisten = \"0.0.0.0:9\"\n").unwrap();
        assert!(format!("{:#}", bad_listen.validate().unwrap_err()).contains("E0656"));
        let bad_otlp: Config =
            toml::from_str("[telemetry.otlp]\nenabled = true\nendpoint = \"localhost:4317\"\n")
                .unwrap();
        assert!(format!("{:#}", bad_otlp.validate().unwrap_err()).contains("E0651"));
        // A disabled section is not checked, as at startup.
        let off: Config =
            toml::from_str("[metrics]\nenabled = false\nlisten = \"nonsense\"\n").unwrap();
        off.validate().unwrap();
    }

    #[test]
    fn trust_requires_capability_tokens_unless_told_otherwise() {
        let cfg: Config = toml::from_str("").expect("empty config");
        assert!(
            cfg.trust.require_capability_tokens,
            "fail closed by default"
        );
        let cfg: Config = toml::from_str("[trust]\nrequire_capability_tokens = false\n")
            .expect("migration setting");
        assert!(!cfg.trust.require_capability_tokens);
        assert!(
            toml::from_str::<Config>("[trust]\nrequire_tokens = false\n").is_err(),
            "a typo is a startup error, not a silently ignored setting"
        );
    }
}
