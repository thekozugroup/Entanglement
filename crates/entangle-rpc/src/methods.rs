use serde::{Deserialize, Serialize};

/// Version information returned by the `version` RPC method.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionResult {
    /// `entangled` daemon version string.
    pub entangled: String,
    /// Underlying Wasm runtime version string (e.g. `wasmtime-43`).
    pub runtime: String,
    /// `entangle-types` crate version string.
    pub types: String,
}

/// Result of the `time` RPC method (used by `entangle doctor` for clock-skew).
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimeResult {
    /// Daemon's view of UNIX epoch time in milliseconds.
    pub unix_millis: u64,
}

/// Result of the `plugins/list` RPC method.
#[derive(Debug, Serialize, Deserialize)]
pub struct PluginsListResult {
    /// Ids of currently loaded plugins.
    pub plugins: Vec<String>,
}

/// Parameters for the `plugins/load` RPC method.
#[derive(Debug, Serialize, Deserialize)]
pub struct PluginsLoadParams {
    /// Path to the directory containing the plugin artefact.
    pub dir: String,
}

/// Result of the `plugins/load` RPC method.
#[derive(Debug, Serialize, Deserialize)]
pub struct PluginsLoadResult {
    /// Id assigned to the newly loaded plugin.
    pub plugin_id: String,
}

/// Parameters for the `plugins/unload` RPC method.
#[derive(Debug, Serialize, Deserialize)]
pub struct PluginsUnloadParams {
    /// Id of the plugin to unload.
    pub plugin_id: String,
}

/// Parameters for the `plugins/invoke` RPC method.
///
/// Note: `plugins/invoke` is planned for the daemon.
#[derive(Debug, Serialize, Deserialize)]
pub struct PluginsInvokeParams {
    /// Id of the plugin to invoke.
    pub plugin_id: String,
    /// Raw input bytes; serialised as a JSON array of numbers.
    pub input: Vec<u8>,
    /// Maximum time the invocation may take, in milliseconds.
    pub timeout_ms: u64,
}

/// Result of the `plugins/invoke` RPC method.
#[derive(Debug, Serialize, Deserialize)]
pub struct PluginsInvokeResult {
    /// Raw output bytes returned by the plugin.
    pub output: Vec<u8>,
}

// ── mesh/peers + mesh/status types ──────────────────────────────────────────

/// A single peer entry returned by `mesh/peers`.
#[derive(Debug, Serialize, Deserialize)]
pub struct MeshPeer {
    /// Peer id as a hex string derived from the peer's Ed25519 public key.
    pub peer_id: String,
    /// Human-readable display name advertised by the peer.
    pub display_name: String,
    /// Network addresses at which the peer was last seen (e.g. `"192.168.1.5:7001"`).
    pub addresses: Vec<String>,
    /// Primary port the peer listens on.
    pub port: u16,
    /// Peer's self-reported version string.
    pub version: String,
    /// Seconds since the peer was last observed on the mesh.
    pub last_seen_secs_ago: u64,
    /// `true` when the peer is present (and not revoked) in the local PeerStore.
    pub trusted: bool,
}

/// Result of the `mesh/peers` RPC method.
#[derive(Debug, Serialize, Deserialize)]
pub struct MeshPeersResult {
    /// Peers currently known to the daemon.
    pub peers: Vec<MeshPeer>,
}

/// Result of the `mesh/status` RPC method.
#[derive(Debug, Serialize, Deserialize)]
pub struct MeshStatusResult {
    /// This node's own peer id in hex.
    pub local_peer_id: String,
    /// This node's display name.
    pub local_display_name: String,
    /// Active transport names (e.g. `["mesh.local"]` in Phase 1).
    pub transports_active: Vec<String>,
    /// Number of peers seen via discovery (may include untrusted peers).
    pub seen_peer_count: usize,
    /// Number of peers in the local PeerStore with trust != Revoked.
    pub trusted_peer_count: usize,
}

// ── compute/dispatch types ───────────────────────────────────────────────────

/// Integrity mode for a compute dispatch request.
///
/// Serialised as a tagged union with `kind` discriminant (kebab-case).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ComputeIntegrity {
    /// No integrity checking; accept the first response.
    None,
    /// Run N identical replicas; a strict majority must return byte-for-byte
    /// identical output.
    Deterministic {
        /// Number of independent execution replicas.
        replicas: u8,
    },
    /// Accept output only from explicitly allow-listed peers (hex peer ids).
    TrustedExecutor {
        /// Hex-encoded peer ids whose outputs are trusted without further verification.
        allowlist: Vec<String>,
    },
    /// Replicate on distinct peers and compare the outputs pairwise with a
    /// signed metric component that runs on the daemon (the submitter,
    /// spec §7.5).
    SemanticEquivalent {
        /// Number of replicas (at least 2).
        replicas: u8,
        /// Minimum number of agreeing replica pairs.
        quorum: u8,
        /// Metric plugin id, `<publisher>/<name>@<version>`.
        metric: String,
        /// Absolute path of the metric's signed package directory. The daemon
        /// loads and verifies it against its own keyring when given; when
        /// absent the metric must already be loaded on the daemon.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        metric_dir: Option<String>,
        /// Pairwise distance strictly below which two outputs agree.
        threshold: f64,
    },
}

/// Parameters for the `compute/dispatch` RPC method.
#[derive(Debug, Serialize, Deserialize)]
pub struct ComputeDispatchParams {
    /// Id of the plugin to invoke.
    pub plugin_id: String,
    /// Raw input bytes; serialised as a JSON array of numbers.
    pub input: Vec<u8>,
    /// Maximum wall-clock time for the invocation in milliseconds.
    pub timeout_ms: u64,
    /// Required CPU cores (fractional; 0.0 = no requirement).
    pub cpu_cores: f32,
    /// Required host memory in bytes (0 = no requirement).
    pub memory_bytes: u64,
    /// Whether a GPU is required (simplified for Phase 1).
    pub gpu_required: bool,
    /// Minimum GPU VRAM required in bytes (0 = no requirement).
    pub gpu_vram_min_bytes: u64,
    /// Integrity policy to enforce.
    pub integrity: ComputeIntegrity,
}

/// Result of the `compute/dispatch` RPC method.
#[derive(Debug, Serialize, Deserialize)]
pub struct ComputeDispatchResult {
    /// Hex peer id of the worker that executed the task.
    pub chosen_peer: String,
    /// Placement score assigned to the chosen worker.
    pub score: f32,
    /// Human-readable explanation of the placement decision.
    pub reason: String,
    /// Raw output bytes returned by the plugin.
    pub output: Vec<u8>,
    /// Hex SHA-256 of the canonical integrity policy the task was dispatched
    /// under (INV-INT-1). Absent from daemons that predate it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    /// One audit record per replica, in dispatch order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replicas: Vec<ComputeReplica>,
    /// For semantic-equivalent: `[agreeing pairs, pairs compared]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair_agreement: Option<(usize, usize)>,
}

/// One replica of a `compute/dispatch` task, as audited by the submitter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputeReplica {
    /// Hex peer id of the executor.
    pub peer: String,
    /// `false` when it ran on the daemon's own kernel.
    pub remote: bool,
    /// `canonical` (its output was returned), `agreed`, `disagreed` or
    /// `failed`.
    pub status: String,
    /// Why it failed, for `status = "failed"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Hex policy hash the executor reported observing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_policy_hash: Option<String>,
    /// Size of its output in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_bytes: Option<u64>,
}

// ── metrics/export + diag/mesh types ─────────────────────────────────────────

/// Result of the `metrics/export` RPC method.
#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsExportResult {
    /// The daemon's metrics in the Prometheus text format (version 0.0.4),
    /// exactly what `GET /metrics` serves.
    pub text: String,
}

/// Parameters for the `diag/mesh` RPC method.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DiagMeshParams {
    /// Measure a round trip to every trusted peer on every path that supports
    /// it.
    #[serde(default)]
    pub probe: bool,
    /// Per-peer probe timeout in milliseconds (clamped by the daemon).
    #[serde(default)]
    pub probe_timeout_ms: u64,
}

/// One address this node is reachable at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagEndpoint {
    /// Transport name: `mdns`, `iroh`, `tailscale` or `metrics`.
    pub transport: String,
    /// The `ip:port` (or long address) peers can use.
    pub address: String,
}

/// The `mesh.tailscale` liveness state, as the daemon last confirmed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagTailscale {
    /// `active`, `stopped`, `uninstalled` or `unknown` (not yet polled).
    pub state: String,
    /// Why the tailnet is stopped (e.g. `NeedsLogin`), if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Seconds since the last confirmed transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_secs: Option<u64>,
    /// Confirmed transitions so far.
    #[serde(default)]
    pub transitions: u64,
    /// Peers currently reachable through the tailnet.
    #[serde(default)]
    pub candidates: usize,
}

/// One way a peer can currently be reached.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiagPath {
    /// `mdns` (sighting), `iroh` (address book) or `tailscale` (candidate).
    pub transport: String,
    /// Address, when the path has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Human-readable detail (`last seen 3s ago`, ...).
    #[serde(default)]
    pub detail: String,
    /// Measured round trip in milliseconds (only with `probe`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
    /// Why the probe failed (only with `probe`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_error: Option<String>,
}

/// A trusted peer and every path it is reachable on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiagPeer {
    /// Peer id (hex).
    pub peer_id: String,
    /// Display name from the peer store.
    pub display_name: String,
    /// Trust level label from the peer store.
    pub trust: String,
    /// Known paths; empty means no transport currently knows how to reach it.
    pub paths: Vec<DiagPath>,
}

/// Result of the `diag/mesh` RPC method.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiagMeshResult {
    /// This node's peer id (hex).
    pub local_peer_id: String,
    /// This node's display name.
    pub local_display_name: String,
    /// `[mesh] transports` as configured.
    pub transports_configured: Vec<String>,
    /// Transports that actually started.
    pub transports_active: Vec<String>,
    /// Local endpoint addresses.
    pub endpoints: Vec<DiagEndpoint>,
    /// Tailnet liveness; absent when `mesh.tailscale` is not running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tailscale: Option<DiagTailscale>,
    /// Trusted (non-revoked) peers.
    pub peers: Vec<DiagPeer>,
    /// mDNS sightings of peers that are *not* trusted.
    #[serde(default)]
    pub untrusted_sightings: usize,
    /// Whether `probe` was requested.
    #[serde(default)]
    pub probed: bool,
}

/// Method name constants — kept in sync between client and server.
pub mod method {
    /// `version` — return daemon / runtime / types version strings.
    pub const VERSION: &str = "version";
    /// `time` — daemon's view of wall-clock UNIX epoch milliseconds.
    pub const TIME: &str = "time";
    /// `plugins/list` — list loaded plugin ids.
    pub const PLUGINS_LIST: &str = "plugins/list";
    /// `plugins/load` — load a plugin from a directory path.
    pub const PLUGINS_LOAD: &str = "plugins/load";
    /// `plugins/unload` — unload a plugin by id.
    pub const PLUGINS_UNLOAD: &str = "plugins/unload";
    /// `plugins/invoke` — invoke a plugin (daemon support planned).
    pub const PLUGINS_INVOKE: &str = "plugins/invoke";
    /// `mesh/peers` — list peers seen on the mesh.
    pub const MESH_PEERS: &str = "mesh/peers";
    /// `mesh/status` — local mesh state: own peer id, transports, counts.
    pub const MESH_STATUS: &str = "mesh/status";
    /// `compute/dispatch` — dispatch a one-shot task via the scheduler.
    pub const COMPUTE_DISPATCH: &str = "compute/dispatch";
    /// `security/plan-max-tier` — list the loaded plugins a new
    /// `[security] max_tier_allowed` would affect, changing nothing.
    pub const SECURITY_PLAN_MAX_TIER: &str = "security/plan-max-tier";
    /// `security/apply-max-tier` — apply a new tier ceiling at runtime,
    /// unloading plugins above it when asked to.
    pub const SECURITY_APPLY_MAX_TIER: &str = "security/apply-max-tier";
    /// `security/cancel-max-tier` — record that the operator cancelled a
    /// ceiling lowering (`ENTANGLE-I0216`).
    pub const SECURITY_CANCEL_MAX_TIER: &str = "security/cancel-max-tier";
    /// `metrics/export` — the Prometheus exposition of the daemon's registry.
    pub const METRICS_EXPORT: &str = "metrics/export";
    /// `diag/mesh` — mesh triage report (transports, endpoints, peer paths).
    pub const DIAG_MESH: &str = "diag/mesh";
}

/// Parameters of `security/plan-max-tier` and `security/cancel-max-tier`.
#[derive(Debug, Serialize, Deserialize)]
pub struct MaxTierParams {
    /// The requested ceiling (1..=5).
    pub max_tier: u8,
}

/// One loaded plugin a lowered ceiling would unload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AffectedPlugin {
    /// Plugin id.
    pub plugin_id: String,
    /// Its effective tier (1..=5).
    pub tier: u8,
    /// True for a native subprocess, false for a Wasm component.
    pub native: bool,
    /// Seconds since it was loaded.
    pub uptime_secs: u64,
}

/// Result of `security/plan-max-tier`.
#[derive(Debug, Serialize, Deserialize)]
pub struct MaxTierPlan {
    /// The ceiling currently in force.
    pub current: u8,
    /// The requested ceiling.
    pub requested: u8,
    /// Loaded plugins above the requested ceiling (empty when raising).
    pub affected: Vec<AffectedPlugin>,
}

/// Parameters of `security/apply-max-tier`.
#[derive(Debug, Serialize, Deserialize)]
pub struct MaxTierApplyParams {
    /// The new ceiling (1..=5).
    pub max_tier: u8,
    /// Unload plugins above the new ceiling. When `false` and any exist, the
    /// call fails and changes nothing — the daemon never unloads silently.
    pub unload: bool,
    /// The plugin ids the operator was shown and agreed to unload. When set,
    /// any other plugin above the new ceiling (e.g. loaded while the prompt
    /// waited) makes the call fail with `ENTANGLE-E0758`, changing nothing.
    /// Absent: every plugin above the ceiling may be unloaded
    /// (`--force-unload`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed: Option<Vec<String>>,
}

/// Result of `security/apply-max-tier`.
#[derive(Debug, Serialize, Deserialize)]
pub struct MaxTierApplied {
    /// Ceiling before the call.
    pub old: u8,
    /// Ceiling now in force.
    pub new: u8,
    /// Ids of the plugins unloaded to honour it.
    pub unloaded: Vec<String>,
}
