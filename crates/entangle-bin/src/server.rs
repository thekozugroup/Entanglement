//! Unix-domain-socket RPC server.
//!
//! Wire format: newline-delimited JSON-RPC 2.0. One request per line,
//! one response per line. Debug-friendly with `nc -U ~/.entangle/sock`.

use crate::methods;
use crate::state::DaemonState;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

/// Bind a Unix-domain socket at `socket_path` and accept connections
/// indefinitely, spawning a task per client.
///
/// All RPC handlers receive the full `Arc<DaemonState>` so they can reach
/// the kernel, dispatcher, peer store, and identity without rebuilding them
/// per-call.
///
/// Returns an error if the socket cannot be bound.
pub async fn serve(socket_path: PathBuf, state: Arc<DaemonState>) -> anyhow::Result<()> {
    // Remove stale socket file so bind succeeds after a crash.
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    // Ensure parent directory exists.
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(&socket_path)?;

    // Restrict permissions to owner-only (0o600) so only the current user
    // can connect.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600));
    }

    tracing::info!(socket_path = %socket_path.display(), "RPC server listening");

    loop {
        let (stream, _addr) = listener.accept().await?;
        let s = state.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_client(stream, s).await {
                tracing::warn!(error = %e, "client task ended with error");
            }
        });
    }
}

async fn serve_client(stream: UnixStream, state: Arc<DaemonState>) -> anyhow::Result<()> {
    let (rd, mut wr) = stream.into_split();
    let mut lines = BufReader::new(rd).lines();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let resp = methods::dispatch(&line, &state).await;
        wr.write_all(resp.as_bytes()).await?;
        wr.write_all(b"\n").await?;
        wr.flush().await?;
    }

    Ok(())
}
