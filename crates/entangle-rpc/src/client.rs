use crate::{errors::RpcError, methods::*};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[derive(Serialize)]
struct Request<'a, P> {
    id: u64,
    jsonrpc: &'static str,
    method: &'a str,
    params: P,
}

// In JSON an octet can require three decimal digits and a separator. Allow
// room for the result envelope in addition to a full-size component output.
const MAX_BINARY_REPLY_BYTES: u64 =
    4 * entangle_types::task::OneShotTask::DEFAULT_MAX_OUTPUT_BYTES + 64 * 1024;

#[derive(Deserialize)]
struct Response<'a> {
    #[serde(default)]
    jsonrpc: serde_json::Value,
    #[serde(default)]
    id: serde_json::Value,
    #[serde(default, borrow, deserialize_with = "present")]
    result: Option<&'a serde_json::value::RawValue>,
    #[serde(default, borrow, deserialize_with = "present")]
    error: Option<&'a serde_json::value::RawValue>,
}

// A present JSON null is a valid result for several methods. Only a missing
// field means the daemon omitted its result.
fn present<'de, T: Deserialize<'de>, D: Deserializer<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

async fn read_reply(reader: impl AsyncRead + Unpin, max_bytes: u64) -> Result<Vec<u8>, RpcError> {
    let mut bytes = Vec::new();
    BufReader::new(reader)
        .take(max_bytes.saturating_add(1))
        .read_until(b'\n', &mut bytes)
        .await?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err(RpcError::Malformed("empty response".into()));
    }
    if bytes.len() as u64 > max_bytes {
        return Err(RpcError::Malformed(
            "binary reply exceeds the JSON-RPC frame limit".into(),
        ));
    }
    Ok(bytes)
}

fn decode_reply<R: DeserializeOwned>(bytes: &[u8], id: u64) -> Result<R, RpcError> {
    // Decode binary arrays directly into Vec<u8>. An intermediate JSON Value
    // would allocate one tree node for every byte of a returned tile.
    let reply: Response = serde_json::from_slice(bytes)?;
    if reply.jsonrpc != "2.0" || reply.id.as_u64() != Some(id) {
        return Err(RpcError::Malformed(
            "unexpected JSON-RPC version or response id".into(),
        ));
    }
    match (reply.result, reply.error) {
        (Some(raw), None) => Ok(serde_json::from_str(raw.get())?),
        (None, Some(raw)) => {
            let error: serde_json::Value = serde_json::from_str(raw.get())?;
            let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(-32000) as i32;
            let message = error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_owned();
            Err(RpcError::Rpc { code, message })
        }
        (Some(_), Some(_)) => Err(RpcError::Malformed(
            "response contains both result and error".into(),
        )),
        (None, None) => Err(RpcError::Malformed("missing result".into())),
    }
}

/// Default connect timeout: 2 seconds. Short enough to fail fast in the CLI;
/// long enough to tolerate a daemon that's just started up.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// A typed JSON-RPC 2.0 client that connects to the `entangled` daemon over
/// its Unix-domain socket.
///
/// Each method call opens a fresh connection, sends one request, and reads one
/// response. The daemon uses newline-delimited JSON framing.
pub struct Client {
    socket_path: PathBuf,
    next_id: AtomicU64,
    connect_timeout: Duration,
}

impl Client {
    /// Create a client targeting the given socket path with the default
    /// 2-second connect timeout.
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            next_id: AtomicU64::new(1),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }

    /// Override the connect timeout used for every call.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Currently-configured connect timeout.
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
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
        let line = serde_json::to_vec(&Request {
            id,
            jsonrpc: "2.0",
            method,
            params,
        })?;

        let stream =
            tokio::time::timeout(self.connect_timeout, UnixStream::connect(&self.socket_path))
                .await
                .map_err(|_| RpcError::ConnectTimeout {
                    socket: self.socket_path.clone(),
                    timeout: self.connect_timeout,
                })??;
        let (rd, mut wr) = stream.into_split();

        wr.write_all(&line).await?;
        drop(line);
        wr.write_all(b"\n").await?;
        wr.flush().await?;

        let limit = match method {
            method::COMPUTE_DISPATCH => MAX_BINARY_REPLY_BYTES,
            _ => u64::MAX,
        };
        decode_reply(&read_reply(rd, limit).await?, id)
    }

    /// Retrieve Prometheus exposition from the running daemon.
    pub async fn metrics(&self) -> Result<String, RpcError> {
        self.call(method::METRICS, serde_json::Value::Null).await
    }

    /// Review, apply or cancel an operator tier change.
    pub async fn tier_policy(&self, params: TierPolicyParams) -> Result<TierReview, RpcError> {
        self.call(method::TIER_POLICY, params).await
    }

    /// `version` — return daemon / runtime / types version strings.
    pub async fn version(&self) -> Result<VersionResult, RpcError> {
        self.call(method::VERSION, serde_json::Value::Null).await
    }

    /// `time` — daemon's view of wall-clock UNIX epoch milliseconds.
    pub async fn time(&self) -> Result<TimeResult, RpcError> {
        self.call(method::TIME, serde_json::Value::Null).await
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
    /// Note: `plugins/invoke` is planned for the daemon side.
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

    /// `mesh/peers` — list peers seen on the mesh.
    pub async fn mesh_peers(&self) -> Result<MeshPeersResult, RpcError> {
        self.call(method::MESH_PEERS, serde_json::Value::Null).await
    }

    /// `mesh/status` — local mesh state: own peer id, transports, peer counts.
    pub async fn mesh_status(&self) -> Result<MeshStatusResult, RpcError> {
        self.call(method::MESH_STATUS, serde_json::Value::Null)
            .await
    }

    /// Submit one signed frame through a selected paired bridge.
    pub async fn relay_send(&self, frame: &RelaySend) -> Result<(), RpcError> {
        self.call("mesh/relay/send", frame).await
    }
    /// Pop the next verified frame from this receiver's inbox.
    pub async fn relay_read(&self) -> Result<Option<RelayMessage>, RpcError> {
        self.call("mesh/relay/read", ()).await
    }

    /// Start a streaming invocation and return its local session handle.
    pub async fn stream_open(&self, params: &StreamOpenParams) -> Result<StreamHandle, RpcError> {
        self.call("compute/stream/open", params).await
    }
    /// Pull the next verified chunk or control event.
    pub async fn stream_read(&self, session: &str) -> Result<StreamRead, RpcError> {
        self.call("compute/stream/read", session).await
    }
    /// Cancel an open session and release its worker reservation.
    pub async fn stream_close(&self, session: &str) -> Result<(), RpcError> {
        self.call("compute/stream/close", session).await
    }

    /// `compute/dispatch` — dispatch a one-shot task via the scheduler.
    pub async fn compute_dispatch(
        &self,
        params: impl std::borrow::Borrow<ComputeDispatchParams>,
    ) -> Result<ComputeDispatchResult, RpcError> {
        self.call(method::COMPUTE_DISPATCH, params.borrow()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nullable_result_is_distinct_from_a_missing_or_ambiguous_result() {
        let null = br#"{"id":1,"jsonrpc":"2.0","result":null}"#;
        assert!(decode_reply::<Option<Vec<u8>>>(null, 1).unwrap().is_none());
        for invalid in [
            br#"{"id":1,"jsonrpc":"2.0"}"#.as_slice(),
            br#"{"id":1,"jsonrpc":"2.0","result":null,"error":null}"#,
            br#"{"id":1,"jsonrpc":"2.0","result":123,"error":{}}"#,
            br#"{"id":2,"jsonrpc":"2.0","result":123}"#,
        ] {
            assert!(matches!(
                decode_reply::<()>(invalid, 1),
                Err(RpcError::Malformed(_))
            ));
        }
        assert!(matches!(
            decode_reply::<()>(null, 2),
            Err(RpcError::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn reply_frame_accepts_exact_cap_and_refuses_one_more_byte() {
        assert_eq!(read_reply(&b"abc\n"[..], 3).await.unwrap(), b"abc");
        assert_eq!(read_reply(&b"abc"[..], 3).await.unwrap(), b"abc");
        assert!(matches!(
            read_reply(&b"abcd\n"[..], 3).await,
            Err(RpcError::Malformed(_))
        ));
    }

    #[test]
    fn default_connect_timeout_is_two_seconds() {
        let c = Client::new("/tmp/nope.sock");
        assert_eq!(c.connect_timeout(), Duration::from_secs(2));
    }

    #[test]
    fn with_connect_timeout_overrides() {
        let c = Client::new("/tmp/nope.sock").with_connect_timeout(Duration::from_millis(50));
        assert_eq!(c.connect_timeout(), Duration::from_millis(50));
    }

    #[tokio::test]
    async fn missing_socket_yields_daemon_not_running() {
        let c = Client::new("/var/empty/no-such-socket-2026.sock");
        let err = c.version().await.expect_err("missing socket must error");
        match err {
            RpcError::DaemonNotRunning(p) => {
                assert!(p.ends_with("no-such-socket-2026.sock"));
            }
            other => panic!("expected DaemonNotRunning, got: {other:?}"),
        }
    }
}
