use crate::{errors::RpcError, methods::*};
use serde::{de::DeserializeOwned, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// A typed JSON-RPC 2.0 client that connects to the `entangled` daemon over
/// its Unix-domain socket.
///
/// Each method call opens a fresh connection, sends one request, and reads one
/// response. The daemon uses newline-delimited JSON framing.
pub struct Client {
    socket_path: PathBuf,
    next_id: AtomicU64,
}

impl Client {
    /// Create a client targeting the given socket path.
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            next_id: AtomicU64::new(1),
        }
    }

    /// Return the default socket path: `$HOME/.entangle/sock`.
    pub fn default_socket() -> PathBuf {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default()
            .join(".entangle/sock")
    }

    /// Low-level call: serialise `params`, send over UDS, deserialise result.
    async fn call<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R, RpcError> {
        if !self.socket_path.exists() {
            return Err(RpcError::DaemonNotRunning(self.socket_path.clone()));
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let line = serde_json::to_string(&req)?;

        let stream = UnixStream::connect(&self.socket_path).await?;
        let (rd, mut wr) = stream.into_split();

        wr.write_all(line.as_bytes()).await?;
        wr.write_all(b"\n").await?;
        wr.flush().await?;

        let mut lines = BufReader::new(rd).lines();
        let resp_line = lines
            .next_line()
            .await?
            .ok_or_else(|| RpcError::Malformed("empty response".into()))?;

        let resp: serde_json::Value = serde_json::from_str(&resp_line)?;

        if let Some(err) = resp.get("error") {
            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-32000) as i32;
            let message = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_string();
            return Err(RpcError::Rpc { code, message });
        }

        let result = resp
            .get("result")
            .ok_or_else(|| RpcError::Malformed("missing result".into()))?
            .clone();

        let typed: R = serde_json::from_value(result)?;
        Ok(typed)
    }

    /// `version` — return daemon / runtime / types version strings.
    pub async fn version(&self) -> Result<VersionResult, RpcError> {
        self.call(method::VERSION, serde_json::Value::Null).await
    }

    /// `plugins/list` — return the ids of currently loaded plugins.
    pub async fn plugins_list(&self) -> Result<PluginsListResult, RpcError> {
        self.call(method::PLUGINS_LIST, serde_json::Value::Null)
            .await
    }

    /// `plugins/load` — ask the daemon to load the plugin at `dir`.
    pub async fn plugins_load(&self, dir: impl AsRef<Path>) -> Result<PluginsLoadResult, RpcError> {
        let p = PluginsLoadParams {
            dir: dir.as_ref().to_string_lossy().into_owned(),
        };
        self.call(method::PLUGINS_LOAD, p).await
    }

    /// `plugins/unload` — unload a plugin by id.
    pub async fn plugins_unload(&self, plugin_id: &str) -> Result<(), RpcError> {
        let p = PluginsUnloadParams {
            plugin_id: plugin_id.into(),
        };
        // Server returns `null` on success; we discard it.
        let _: serde_json::Value = self.call(method::PLUGINS_UNLOAD, p).await?;
        Ok(())
    }

    /// `plugins/invoke` — invoke a plugin with raw bytes input.
    ///
    /// Note: `plugins/invoke` is planned for iter 5 on the daemon side.
    pub async fn plugins_invoke(
        &self,
        plugin_id: &str,
        input: Vec<u8>,
        timeout_ms: u64,
    ) -> Result<PluginsInvokeResult, RpcError> {
        let p = PluginsInvokeParams {
            plugin_id: plugin_id.into(),
            input,
            timeout_ms,
        };
        self.call(method::PLUGINS_INVOKE, p).await
    }

    /// `mesh/peers` — list peers seen on the mesh (iter 9).
    pub async fn mesh_peers(&self) -> Result<MeshPeersResult, RpcError> {
        self.call(method::MESH_PEERS, serde_json::Value::Null).await
    }

    /// `mesh/status` — local mesh state: own peer id, transports, peer counts (iter 9).
    pub async fn mesh_status(&self) -> Result<MeshStatusResult, RpcError> {
        self.call(method::MESH_STATUS, serde_json::Value::Null)
            .await
    }

    /// `compute/dispatch` — dispatch a one-shot task via the scheduler (iter 24).
    pub async fn compute_dispatch(
        &self,
        params: ComputeDispatchParams,
    ) -> Result<ComputeDispatchResult, RpcError> {
        self.call(method::COMPUTE_DISPATCH, params).await
    }
}
