//! The daemon side of the gateway's built-in `entangle` server (spec §8.3):
//! loaded plugins, listed and invoked over the daemon's RPC socket
//! (`plugins/list`, `perms/list` for tiers, `plugins/invoke`).
//!
//! Everything goes through the daemon, so its rules apply unchanged: a
//! plugin over `[security] max_tier_allowed` or in `[plugins] disabled` is
//! not loaded and therefore neither listed nor callable, and capability
//! grants are whatever the daemon gave the plugin.

use entangle_agent_host::builtin::{BoxFuture, PluginBackend, PluginTool};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

/// [`PluginBackend`] over the daemon's RPC socket.
pub(crate) struct DaemonPlugins {
    client: entangle_rpc::Client,
    socket: PathBuf,
}

impl std::fmt::Debug for DaemonPlugins {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonPlugins")
            .field("socket", &self.socket)
            .finish()
    }
}

impl DaemonPlugins {
    /// A backend talking to the daemon at `socket`. A daemon response
    /// longer than `max_reply` bytes is refused while it is read, not
    /// after: pass the gateway's reply cap so plugin output is never held
    /// in memory beyond what the gateway would forward.
    pub(crate) fn new(socket: PathBuf, max_reply: usize) -> Self {
        Self {
            client: entangle_rpc::Client::new(&socket).with_max_response_bytes(max_reply),
            socket,
        }
    }

    /// The default daemon socket (`$HOME/.entangle/sock`).
    pub(crate) fn default_socket() -> PathBuf {
        entangle_rpc::Client::default_socket()
    }

    /// The loaded plugins, or why the daemon cannot be asked.
    pub(crate) async fn loaded(&self) -> Result<Vec<PluginTool>, String> {
        let ids = self
            .client
            .plugins_list()
            .await
            .map_err(|e| {
                format!(
                    "the daemon at {} cannot be reached: {e}",
                    self.socket.display()
                )
            })?
            .plugins;
        // Tiers are informational (shown in tool descriptions): a daemon
        // that cannot answer `perms/list` still serves its plugins.
        let tiers: BTreeMap<String, u8> = match self.client.perms_list(None).await {
            Ok(p) => p
                .plugins
                .into_iter()
                .map(|p| (p.plugin_id, p.effective_tier))
                .collect(),
            Err(_) => BTreeMap::new(),
        };
        Ok(ids
            .into_iter()
            .map(|plugin_id| PluginTool {
                tier: tiers.get(&plugin_id).copied(),
                plugin_id,
            })
            .collect())
    }
}

impl PluginBackend for DaemonPlugins {
    fn list(&self) -> BoxFuture<'_, Result<Vec<PluginTool>, String>> {
        Box::pin(self.loaded())
    }

    fn invoke(
        &self,
        plugin_id: &str,
        input: Vec<u8>,
        timeout: Duration,
    ) -> BoxFuture<'_, Result<Vec<u8>, String>> {
        let plugin_id = plugin_id.to_owned();
        Box::pin(async move {
            let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
            self.client
                .plugins_invoke(&plugin_id, input, timeout_ms)
                .await
                .map(|r| r.output)
                .map_err(|e| e.to_string())
        })
    }
}
