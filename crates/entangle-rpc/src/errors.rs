/// Errors returned by [`crate::Client`] operations.
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    /// An I/O error occurred on the underlying Unix-domain socket.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// The response could not be serialised or deserialised as JSON.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    /// The daemon returned a JSON-RPC error object.
    #[error("rpc {code}: {message}")]
    Rpc {
        /// JSON-RPC error code (e.g. `-32601` for method-not-found).
        code: i32,
        /// Human-readable error message from the server.
        message: String,
    },

    /// The socket file does not exist; the daemon is not running.
    #[error("daemon not running at {0}")]
    DaemonNotRunning(std::path::PathBuf),

    /// Connecting to the daemon timed out after the given duration.
    #[error("connect timeout after {0:?}")]
    ConnectTimeout(std::time::Duration),

    /// The response did not conform to the expected JSON-RPC 2.0 structure.
    #[error("malformed response: {0}")]
    Malformed(String),
}
