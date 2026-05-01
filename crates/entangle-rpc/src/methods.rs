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
}
