//! Unix-domain-socket RPC server.
//!
//! Wire format: newline-delimited JSON-RPC 2.0. One request per line,
//! one response per line. Debug-friendly with `nc -U ~/.entangle/sock`, once
//! the first line carries the token (see Hardening).
//!
//! # Hardening
//!
//! - Request lines are capped at [`MAX_REQUEST_BYTES`]; an over-cap line gets
//!   a JSON-RPC `-32600` error and the connection is closed, so a client
//!   cannot force an unbounded allocation.
//! - The accept loop survives transient `accept()` failures (e.g. `EMFILE`)
//!   with bounded exponential backoff instead of killing the control plane.
//! - At most [`MAX_CONCURRENT_CLIENTS`] connections are served at once, and a
//!   connection idle for [`CLIENT_READ_TIMEOUT`] is reaped.
//! - The socket's parent directory is created mode `0700`, the socket itself
//!   is forced to `0600` (the server refuses to run otherwise), stale socket
//!   files are only unlinked when they really are sockets, and each accepted
//!   peer must present the owner's uid via `SO_PEERCRED`.
//! - At each start a random token is written to a `0600` file next to the
//!   socket (`<socket>.token`, see [`entangle_rpc::auth`]); the first line
//!   of every connection must present it, or the connection gets a
//!   `-32001` error and is closed before any method is dispatched. A
//!   process confined by the agent sandbox can connect to the socket (the
//!   sandbox does not mediate `connect()`) but cannot read the token.

use crate::methods;
use crate::state::DaemonState;
use anyhow::Context as _;
use entangle_types::task::OneShotTask;
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

/// Maximum accepted length of one request line in bytes, excluding the
/// trailing `\n`.
///
/// Sized above the JSON-inflated ceiling of the largest legal payload: task
/// input travels as a JSON array of numbers (`[255,255,…]`), which expands
/// raw bytes by up to ~4x, and [`OneShotTask::DEFAULT_MAX_INPUT_BYTES`] is
/// 16 MiB — so 64 MiB of inflated payload plus 64 KiB of envelope headroom.
pub const MAX_REQUEST_BYTES: usize = 4 * OneShotTask::DEFAULT_MAX_INPUT_BYTES as usize + 64 * 1024;

/// Maximum number of concurrently served client connections. Additional
/// connections wait in the listen backlog until a permit frees up.
pub const MAX_CONCURRENT_CLIENTS: usize = 128;

/// How long a connected client may sit idle (or stall mid-request) before
/// the connection is reaped. Bounds how long a stalled client can hold one
/// of the [`MAX_CONCURRENT_CLIENTS`] permits.
pub const CLIENT_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Consecutive `accept()` failures tolerated before the server gives up.
const MAX_CONSECUTIVE_ACCEPT_ERRORS: u32 = 128;

/// Upper bound on the per-error accept backoff sleep.
const ACCEPT_BACKOFF_CAP: Duration = Duration::from_secs(1);

/// A bound RPC socket, already restricted to its owner: what [`bind`]
/// returns and [`serve_listener`] accepts on.
pub struct BoundSocket {
    listener: UnixListener,
    owner_uid: u32,
    path: PathBuf,
    token: Arc<str>,
}

impl BoundSocket {
    /// The socket's path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Bind a Unix-domain socket at `socket_path` and accept connections
/// indefinitely, spawning a task per client: [`bind`] then
/// [`serve_listener`].
///
/// All RPC handlers receive the full `Arc<DaemonState>` so they can reach
/// the kernel, dispatcher, peer store, and identity without rebuilding them
/// per-call.
///
/// Returns an error if the socket cannot be bound, if its permissions cannot
/// be restricted to owner-only, or if `accept()` fails
/// `MAX_CONSECUTIVE_ACCEPT_ERRORS` times in a row.
pub async fn serve(socket_path: PathBuf, state: Arc<DaemonState>) -> anyhow::Result<()> {
    let bound = bind(&socket_path)?;
    serve_listener(bound, state).await
}

/// Create the socket's private parent directory, replace a stale socket,
/// bind, and restrict the socket to mode `0600`. Synchronous, so a daemon can
/// have the socket on disk (and registered for removal on a fault exit)
/// before it starts any task that could fail. Must run inside a Tokio
/// runtime (the listener registers with its reactor).
pub fn bind(socket_path: &Path) -> anyhow::Result<BoundSocket> {
    // Ensure the parent directory exists and is private to the owner.
    if let Some(parent) = socket_path.parent() {
        if !parent.as_os_str().is_empty() {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(parent).with_context(|| {
                format!("failed to create socket directory {}", parent.display())
            })?;
        }
    }

    // Remove a stale socket file so bind succeeds after a crash — but only
    // if the existing path really is a socket. Anything else (regular file,
    // directory, symlink) is suspicious and must not be unlinked blindly.
    match std::fs::symlink_metadata(socket_path) {
        Ok(meta) if meta.file_type().is_socket() => {
            std::fs::remove_file(socket_path).with_context(|| {
                format!("failed to remove stale socket {}", socket_path.display())
            })?;
        }
        Ok(meta) => anyhow::bail!(
            "refusing to replace {}: existing path is not a socket ({:?})",
            socket_path.display(),
            meta.file_type()
        ),
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => {
            return Err(e).with_context(|| {
                format!("failed to inspect socket path {}", socket_path.display())
            });
        }
    }

    // The token exists before the socket does, so a client that can
    // connect can also find it.
    let token = write_token(socket_path)?;
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("failed to bind {}", socket_path.display()))?;

    // Restrict permissions to owner-only (0o600) so only the current user
    // can connect; refuse to serve if that does not stick.
    let owner_uid = restrict_socket(socket_path)?;
    Ok(BoundSocket {
        listener,
        owner_uid,
        path: socket_path.to_path_buf(),
        token: token.into(),
    })
}

/// Write a fresh random connection token to `<socket>.token` (mode `0600`,
/// replacing any earlier one atomically) and return it.
fn write_token(socket_path: &Path) -> anyhow::Result<String> {
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut raw = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut raw))
        .context("reading /dev/urandom for the RPC token")?;
    let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let path = entangle_rpc::auth::token_path(socket_path);
    let tmp = path.with_extension(format!("token.{}.tmp", std::process::id()));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(token.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &path).with_context(|| format!("writing {}", path.display()))?;
    Ok(token)
}

/// Constant-time comparison of two tokens.
fn token_matches(given: &str, expected: &str) -> bool {
    let (a, b) = (given.as_bytes(), expected.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Whether `line` is the authentication line carrying `token`.
fn authenticates(line: &str, token: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
        return false;
    };
    v.get("method").and_then(|m| m.as_str()) == Some(entangle_rpc::auth::AUTH_METHOD)
        && v.pointer("/params/token")
            .and_then(|t| t.as_str())
            .is_some_and(|t| token_matches(t, token))
}

/// Accept connections on a socket from [`bind`] until a fatal accept error.
pub async fn serve_listener(bound: BoundSocket, state: Arc<DaemonState>) -> anyhow::Result<()> {
    let BoundSocket {
        listener,
        owner_uid,
        path: socket_path,
        token,
    } = bound;

    tracing::info!(socket_path = %socket_path.display(), "RPC server listening");

    let clients = Arc::new(Semaphore::new(MAX_CONCURRENT_CLIENTS));
    let mut consecutive_accept_errors: u32 = 0;

    loop {
        // Acquire the connection permit before accepting, so excess clients
        // queue in the listen backlog rather than piling up as tasks.
        let permit = clients
            .clone()
            .acquire_owned()
            .await
            .expect("client semaphore is never closed");

        let stream = match listener.accept().await {
            Ok((stream, _addr)) => {
                consecutive_accept_errors = 0;
                stream
            }
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::ConnectionAborted | ErrorKind::Interrupted
                ) =>
            {
                // Per-connection transient failure; keep accepting.
                continue;
            }
            Err(e) => {
                // Resource exhaustion (EMFILE/ENFILE) surfaces as
                // `ErrorKind::Uncategorized` on stable, so we cannot match it
                // by kind: back off on the catch-all instead of terminating
                // the control plane, and give up only after a long streak.
                consecutive_accept_errors += 1;
                if consecutive_accept_errors >= MAX_CONSECUTIVE_ACCEPT_ERRORS {
                    return Err(e).with_context(|| {
                        format!(
                            "accept failed {consecutive_accept_errors} times in a row; giving up"
                        )
                    });
                }
                let backoff = accept_backoff(consecutive_accept_errors);
                tracing::warn!(
                    error = %e,
                    consecutive = consecutive_accept_errors,
                    backoff_ms = backoff.as_millis() as u64,
                    "accept error; backing off"
                );
                tokio::time::sleep(backoff).await;
                continue;
            }
        };

        // Defense-in-depth on top of the 0600 socket mode: only serve peers
        // running as the socket owner's uid (SO_PEERCRED).
        match stream.peer_cred() {
            Ok(cred) if cred.uid() == owner_uid => {}
            Ok(cred) => {
                tracing::warn!(
                    peer_uid = cred.uid(),
                    owner_uid,
                    "rejecting connection from foreign uid"
                );
                continue;
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to read peer credentials; rejecting connection");
                continue;
            }
        }

        let s = state.clone();
        let token = token.clone();
        tokio::spawn(async move {
            // Hold the permit for the lifetime of the connection.
            let _permit = permit;
            if let Err(e) = serve_client(stream, s, &token, CLIENT_READ_TIMEOUT).await {
                tracing::warn!(error = %e, "client task ended with error");
            }
        });
    }
}

/// Force the socket to mode `0600` and verify no group/other bits remain.
/// Returns the socket owner's uid (the daemon's effective uid at bind time),
/// used for the per-connection peer-credential check.
fn restrict_socket(socket_path: &Path) -> anyhow::Result<u32> {
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600)).with_context(
        || {
            format!(
                "failed to set mode 0600 on socket {}",
                socket_path.display()
            )
        },
    )?;
    let meta = std::fs::metadata(socket_path)
        .with_context(|| format!("failed to stat socket {}", socket_path.display()))?;
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "socket {} is group/world accessible (mode {:o}); refusing to serve",
            socket_path.display(),
            mode & 0o777
        );
    }
    Ok(meta.uid())
}

/// Bounded exponential backoff for consecutive accept errors:
/// 10 ms, 20 ms, 40 ms, … capped at [`ACCEPT_BACKOFF_CAP`].
fn accept_backoff(consecutive_errors: u32) -> Duration {
    let shift = consecutive_errors.saturating_sub(1).min(7);
    Duration::from_millis(10u64 << shift).min(ACCEPT_BACKOFF_CAP)
}

async fn serve_client(
    stream: UnixStream,
    state: Arc<DaemonState>,
    token: &str,
    read_timeout: Duration,
) -> anyhow::Result<()> {
    let (rd, mut wr) = stream.into_split();

    // Allow one byte past the cap so `read_until` can distinguish a line of
    // exactly `MAX_REQUEST_BYTES` plus its delimiter (legal) from a line that
    // exhausted the cap before any delimiter arrived (over-cap).
    let line_limit = MAX_REQUEST_BYTES as u64 + 1;
    let mut reader = BufReader::new(rd).take(line_limit);
    let mut buf: Vec<u8> = Vec::new();
    let mut authenticated = false;

    loop {
        buf.clear();
        reader.set_limit(line_limit);

        let n = match tokio::time::timeout(read_timeout, reader.read_until(b'\n', &mut buf)).await {
            Ok(read) => read?,
            Err(_elapsed) => {
                tracing::debug!("client read timed out; reaping connection");
                return Ok(());
            }
        };
        if n == 0 {
            return Ok(()); // clean EOF
        }

        // `read_until` stops at the delimiter, at EOF, or when the `Take`
        // limit is exhausted. No trailing delimiter *and* more bytes than the
        // cap means the line was truncated at the limit: reject and close
        // without buffering any further client input.
        if buf.last() != Some(&b'\n') && buf.len() > MAX_REQUEST_BYTES {
            let resp = format!(
                r#"{{"jsonrpc":"2.0","id":null,"error":{{"code":-32600,"message":"invalid request: request exceeds {MAX_REQUEST_BYTES} bytes"}}}}"#
            );
            wr.write_all(resp.as_bytes()).await?;
            wr.write_all(b"\n").await?;
            wr.flush().await?;
            return Ok(());
        }

        let line_bytes = match buf.split_last() {
            Some((&b'\n', rest)) => rest,
            // Final line before EOF arrived without a delimiter; serve it
            // like `lines()` used to.
            _ => &buf[..],
        };
        let line = std::str::from_utf8(line_bytes).context("request line is not valid UTF-8")?;
        if line.trim().is_empty() {
            continue;
        }
        if !authenticated {
            if authenticates(line, token) {
                authenticated = true;
                continue;
            }
            let resp = format!(
                r#"{{"jsonrpc":"2.0","id":null,"error":{{"code":{},"message":"unauthorized: the first line of a connection must carry the token from {}"}}}}"#,
                entangle_rpc::auth::UNAUTHORIZED,
                "<socket>.token"
            );
            wr.write_all(resp.as_bytes()).await?;
            wr.write_all(b"\n").await?;
            wr.flush().await?;
            return Ok(());
        }

        let resp = methods::dispatch(line, &state).await;
        wr.write_all(resp.as_bytes()).await?;
        wr.write_all(b"\n").await?;
        wr.flush().await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use entangle_peers::PeerStore;
    use entangle_runtime::{Kernel, KernelConfig};
    use entangle_scheduler::{Dispatcher, WorkerPool};
    use entangle_signing::{IdentityKeyPair, Keyring};
    use entangle_types::peer_id::PeerId;

    fn make_state() -> Arc<DaemonState> {
        let kernel = Arc::new(
            Kernel::new(KernelConfig::default(), Keyring::new())
                .expect("kernel construction must not fail in tests"),
        );
        let worker_pool = WorkerPool::new();
        let identity = IdentityKeyPair::generate();
        let local_peer_id = PeerId::from_public_key_bytes(identity.public().as_bytes());
        let dispatcher = Arc::new(Dispatcher::new(
            worker_pool.clone(),
            kernel.clone(),
            local_peer_id,
        ));
        Arc::new(DaemonState::new(
            kernel,
            dispatcher,
            worker_pool,
            PeerStore::new(),
            identity,
            "test-node".to_owned(),
        ))
    }

    /// N stalled connections (clients that connect but never send a byte)
    /// must all be reaped by the per-read timeout, so they cannot pin
    /// connection permits or buffers forever.
    #[tokio::test(flavor = "multi_thread")]
    async fn stalled_connections_are_reaped_by_read_timeout() {
        let state = make_state();
        let mut held_clients = Vec::new();
        let mut tasks = Vec::new();

        for _ in 0..8 {
            let (client, server) = UnixStream::pair().expect("socketpair");
            held_clients.push(client); // keep the peer open: a genuine stall
            let s = state.clone();
            tasks.push(tokio::spawn(async move {
                serve_client(server, s, "t", Duration::from_millis(100)).await
            }));
        }

        for task in tasks {
            let result = tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .expect("stalled client was not reaped by the read timeout")
                .expect("client task panicked");
            assert!(result.is_ok(), "reaped connection must close cleanly");
        }
        drop(held_clients);
    }

    /// A client that stalls *between* requests is also reaped, after having
    /// been served normally first.
    #[tokio::test(flavor = "multi_thread")]
    async fn active_then_stalled_connection_is_reaped() {
        let state = make_state();
        let (mut client, server) = UnixStream::pair().expect("socketpair");
        let task = tokio::spawn(async move {
            serve_client(server, state, "t", Duration::from_millis(200)).await
        });

        client
            .write_all(format!("{}\n", entangle_rpc::auth::auth_line("t")).as_bytes())
            .await
            .unwrap();
        client
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"version\",\"params\":{}}\n")
            .await
            .unwrap();
        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).expect("valid JSON response");
        assert_eq!(v["id"], 1);
        assert!(v["result"]["entangled"].is_string());

        // Now stall: send nothing further. The server must reap us.
        let result = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("stalled client was not reaped by the read timeout")
            .expect("client task panicked");
        assert!(result.is_ok());
    }

    /// Review finding 1(b): a connection that does not present the token
    /// gets an error and is closed before any method is dispatched; a wrong
    /// token likewise; the right token is served.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_connection_without_the_token_is_refused_before_dispatch() {
        const VERSION: &[u8] =
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"version\",\"params\":{}}\n";
        for first in [
            None,
            Some(entangle_rpc::auth::auth_line("wrong-token")),
            Some(entangle_rpc::auth::auth_line("secret-tokeX")),
        ] {
            let state = make_state();
            let (mut client, server) = UnixStream::pair().expect("socketpair");
            let task = tokio::spawn(async move {
                serve_client(server, state, "secret-token", Duration::from_secs(5)).await
            });
            if let Some(line) = &first {
                client
                    .write_all(format!("{line}\n").as_bytes())
                    .await
                    .unwrap();
            }
            // After a wrong first line the server may already have refused
            // and closed, so this write can fail with EPIPE: that is the
            // behaviour under test, not an error.
            let _ = client.write_all(VERSION).await;
            let mut reader = BufReader::new(client);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let v: serde_json::Value = serde_json::from_str(&line).expect("JSON");
            assert_eq!(v["error"]["code"], -32001, "{first:?}: {line}");
            assert!(v.get("result").is_none());
            // The connection is closed: nothing more is read.
            let mut rest = String::new();
            assert_eq!(reader.read_line(&mut rest).await.unwrap(), 0);
            assert!(task.await.unwrap().is_ok());
        }
        // The right token: served.
        let state = make_state();
        let (mut client, server) = UnixStream::pair().expect("socketpair");
        tokio::spawn(async move {
            serve_client(server, state, "secret-token", Duration::from_secs(5)).await
        });
        let auth = format!("{}\n", entangle_rpc::auth::auth_line("secret-token"));
        client.write_all(auth.as_bytes()).await.unwrap();
        client.write_all(VERSION).await.unwrap();
        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).expect("JSON");
        assert!(v["result"]["entangled"].is_string(), "{line}");
    }

    #[test]
    fn the_token_file_is_private_and_replaced_at_each_bind() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _g = rt.enter();
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("sock");
        let a = bind(&sock).unwrap();
        let path = entangle_rpc::auth::token_path(&sock);
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), &*a.token);
        assert_eq!(a.token.len(), 64);
        let first = a.token.clone();
        drop(a);
        let b = bind(&sock).unwrap();
        assert_ne!(first, b.token, "a new token at each start");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), &*b.token);
    }

    #[test]
    fn accept_backoff_is_monotonic_and_capped() {
        assert_eq!(accept_backoff(1), Duration::from_millis(10));
        assert_eq!(accept_backoff(2), Duration::from_millis(20));
        assert_eq!(accept_backoff(3), Duration::from_millis(40));
        let mut prev = Duration::ZERO;
        for n in 1..=MAX_CONSECUTIVE_ACCEPT_ERRORS {
            let b = accept_backoff(n);
            assert!(b >= prev, "backoff must not shrink");
            assert!(b <= ACCEPT_BACKOFF_CAP, "backoff must stay capped");
            prev = b;
        }
        assert_eq!(prev, ACCEPT_BACKOFF_CAP);
    }
}
