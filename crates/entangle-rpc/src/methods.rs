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
    /// Run N identical replicas; require byte-for-byte identical outputs.
    Deterministic {
        /// Number of independent execution replicas.
        replicas: u8,
    },
    /// Accept output only from explicitly allow-listed peers (hex peer ids).
    TrustedExecutor {
        /// Hex-encoded peer ids whose outputs are trusted without further verification.
        allowlist: Vec<String>,
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
}

/// Method name constants — kept in sync between client and server.
pub mod method {
    /// `version` — return daemon / runtime / types version strings.
    pub const VERSION: &str = "version";
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
}
