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
/// Note: `plugins/invoke` is planned for the daemon in iter 5.
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
    /// `plugins/invoke` — invoke a plugin (daemon support planned for iter 5).
    pub const PLUGINS_INVOKE: &str = "plugins/invoke";
    /// `mesh/peers` — list peers seen on the mesh (iter 9).
    pub const MESH_PEERS: &str = "mesh/peers";
    /// `mesh/status` — local mesh state: own peer id, transports, counts (iter 9).
    pub const MESH_STATUS: &str = "mesh/status";
}
