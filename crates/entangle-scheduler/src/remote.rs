//! Cross-node task dispatch: the client half that ships a task to a peer, and
//! the server half that executes one on behalf of a peer.
//!
//! # Client half
//!
//! [`RemoteDispatch`] turns a `PeerId` chosen by placement into an actual
//! round-trip: resolve the peer to a dialable address via a
//! [`PeerAddressBook`], encode a [`RemoteTaskRequest`], send it over a
//! [`MeshTransport`] speaking [`ALPN_SCHEDULER`], and decode the answer under
//! a deadline. Every failure is a typed [`DispatchError`]; none of them hang.
//!
//! # Server half
//!
//! [`RemoteTaskServer`] is the inverse. **It is the security boundary of this
//! feature**: it turns an inbound frame into a local plugin execution, so
//! everything it accepts is something a remote machine made this machine do.
//!
//! The gate is [`PeerAllowlist`], checked **before the payload is even
//! decoded**:
//!
//! * the peer id is the one QUIC authenticated during the handshake
//!   (`MeshConn::remote_peer_id`), i.e. the peer proved possession of the
//!   Ed25519 secret key behind it — it is not a claim in the payload;
//! * an id absent from the allowlist, or present but revoked, gets
//!   [`RemoteErrorCode::NotAuthorized`] and nothing else happens.
//!
//! On top of that the executor clamps what an authorized peer can ask for:
//! the timeout is capped ([`MAX_REMOTE_TASK_TIMEOUT_MS`]) so a caller cannot
//! pin a worker indefinitely, input and output sizes are capped, and the task
//! always runs with [`IntegrityPolicy::None`] — exactly once — so a caller
//! cannot request N replicas and amplify one frame into N executions.
//!
//! [`ALPN_SCHEDULER`]: entangle_mesh_iroh::ALPN_SCHEDULER
//! [`MeshTransport`]: entangle_mesh_iroh::MeshTransport
//! [`IntegrityPolicy::None`]: entangle_types::task::IntegrityPolicy::None

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use entangle_mesh_iroh::{DynMeshTransport, IrohPeer, MeshIroh};
use entangle_runtime::{Kernel, RuntimeError};
use entangle_types::peer_id::PeerId;
use entangle_types::plugin_id::PluginId;
use entangle_types::resource::ResourceSpec;
use entangle_types::task::{IntegrityPolicy, OneShotTask};
use parking_lot::RwLock;

use crate::dispatcher::DispatchError;
use crate::wire::{
    decode_request, decode_response, encode_request, encode_response, RemoteErrorCode,
    RemoteOutcome, RemoteTaskRequest, RemoteTaskResponse, WireError,
};

// ─── client half ─────────────────────────────────────────────────────────────

/// Resolves a [`PeerId`] to something dialable.
///
/// Placement decides *who* runs a task; this decides *how to reach them*. The
/// two are separate because a peer can be a legitimate placement target long
/// before this node has learned a working address for it.
pub trait PeerAddressBook: std::fmt::Debug + Send + Sync {
    /// The peer's current dialable descriptor, or `None` if unknown.
    fn lookup(&self, peer: &PeerId) -> Option<IrohPeer>;
}

/// A simple in-memory [`PeerAddressBook`], cheap to clone and share.
#[derive(Clone, Debug, Default)]
pub struct PeerDirectory {
    inner: Arc<RwLock<HashMap<PeerId, IrohPeer>>>,
}

impl PeerDirectory {
    /// An empty directory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record (or replace) the address for `peer.peer_id`.
    pub fn insert(&self, peer: IrohPeer) {
        self.inner.write().insert(peer.peer_id, peer);
    }

    /// Forget a peer's address. Returns the previous entry, if any.
    pub fn remove(&self, peer: &PeerId) -> Option<IrohPeer> {
        self.inner.write().remove(peer)
    }

    /// Number of known addresses.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Whether the directory is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

impl PeerAddressBook for PeerDirectory {
    fn lookup(&self, peer: &PeerId) -> Option<IrohPeer> {
        self.inner.read().get(peer).cloned()
    }
}

/// Slack added to a task's own timeout to form the end-to-end deadline for a
/// remote round-trip: connection setup, framing and the return leg.
pub const DEFAULT_REMOTE_OVERHEAD: Duration = Duration::from_secs(10);

/// The client half of cross-node dispatch.
///
/// Holds a transport and an address book. Attach one to a [`Dispatcher`] with
/// [`Dispatcher::with_remote`] to make remote placements actually go remote.
///
/// [`Dispatcher`]: crate::Dispatcher
/// [`Dispatcher::with_remote`]: crate::Dispatcher::with_remote
#[derive(Clone)]
pub struct RemoteDispatch {
    transport: DynMeshTransport,
    addresses: Arc<dyn PeerAddressBook>,
    overhead: Duration,
}

impl std::fmt::Debug for RemoteDispatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteDispatch")
            .field("local_peer_id", &self.transport.local_peer_id())
            .field("addresses", &self.addresses)
            .field("overhead", &self.overhead)
            .finish()
    }
}

impl RemoteDispatch {
    /// Build a client over `transport`, resolving peers through `addresses`.
    ///
    /// `transport` must be speaking [`ALPN_SCHEDULER`]; a transport on another
    /// ALPN will fail to connect rather than silently mis-route.
    ///
    /// [`ALPN_SCHEDULER`]: entangle_mesh_iroh::ALPN_SCHEDULER
    pub fn new(transport: DynMeshTransport, addresses: Arc<dyn PeerAddressBook>) -> Self {
        Self {
            transport,
            addresses,
            overhead: DEFAULT_REMOTE_OVERHEAD,
        }
    }

    /// Override the slack added to the task timeout when forming the deadline.
    #[must_use]
    pub fn with_overhead(mut self, overhead: Duration) -> Self {
        self.overhead = overhead;
        self
    }

    /// This node's own peer id, as the transport reports it.
    pub fn local_peer_id(&self) -> PeerId {
        self.transport.local_peer_id()
    }

    /// Ship `task` to `peer` and return the output bytes it produced.
    ///
    /// The whole exchange is bounded by `task.timeout_ms` plus the configured
    /// overhead, so an unreachable or silent peer yields
    /// [`DispatchError::RemoteTransport`] rather than a hang.
    pub async fn dispatch(
        &self,
        task: &OneShotTask,
        peer: PeerId,
    ) -> Result<Vec<u8>, DispatchError> {
        let addr = self
            .addresses
            .lookup(&peer)
            .ok_or_else(|| DispatchError::RemoteTransport {
                peer,
                reason: "no known network address for this peer (not paired, or no address \
                         learned yet)"
                    .to_owned(),
            })?;

        let request = RemoteTaskRequest::for_task(task);
        let frame = encode_request(&request).map_err(|e| DispatchError::RemoteTransport {
            peer,
            reason: format!("encoding request: {e}"),
        })?;

        let budget = Duration::from_millis(task.timeout_ms).saturating_add(self.overhead);
        let raw = match tokio::time::timeout(budget, self.transport.request(&addr, &frame)).await {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => {
                return Err(DispatchError::RemoteTransport {
                    peer,
                    reason: e.to_string(),
                })
            }
            Err(_elapsed) => {
                return Err(DispatchError::RemoteTransport {
                    peer,
                    reason: format!(
                        "no answer within {}ms (task timeout {}ms + {}ms overhead)",
                        budget.as_millis(),
                        task.timeout_ms,
                        self.overhead.as_millis()
                    ),
                })
            }
        };

        // The peer's answer is untrusted input: size-check it against *our*
        // limit, not anything it told us.
        let response = decode_response(&raw, task.max_output_bytes).map_err(|e| match e {
            WireError::OutputTooLarge { declared, actual } => DispatchError::OutputSizeExceeded(
                entangle_types::errors::EntangleError::OutputSizeExceeded {
                    declared,
                    actual,
                    peer: peer.to_hex(),
                },
            ),
            other => DispatchError::RemoteTransport {
                peer,
                reason: other.to_string(),
            },
        })?;

        match response.outcome {
            RemoteOutcome::Ok { output } => Ok(output),
            RemoteOutcome::Err { code, message } => Err(DispatchError::RemoteRejected {
                peer,
                code,
                message,
            }),
        }
    }
}

// ─── server half ─────────────────────────────────────────────────────────────

/// Decides whether a peer may make this node execute work.
///
/// The daemon implements this over its persisted `PeerStore`; tests use
/// [`StaticAllowlist`]. The `peer` handed to [`PeerAllowlist::is_authorized`]
/// is always transport-authenticated, never self-reported.
pub trait PeerAllowlist: std::fmt::Debug + Send + Sync {
    /// `true` only if `peer` is explicitly trusted to submit work here.
    ///
    /// Implementations must fail **closed**: unknown, revoked, and
    /// error-while-checking all mean `false`.
    fn is_authorized(&self, peer: &PeerId) -> bool;
}

/// A fixed set of authorized peers.
///
/// Useful for tests and for a statically-configured node. An empty allowlist
/// authorizes nobody, which is the correct default.
#[derive(Clone, Debug, Default)]
pub struct StaticAllowlist(HashSet<PeerId>);

impl StaticAllowlist {
    /// An allowlist authorizing nobody.
    pub fn new() -> Self {
        Self::default()
    }

    /// Authorize `peer`.
    #[must_use]
    pub fn allow(mut self, peer: PeerId) -> Self {
        self.0.insert(peer);
        self
    }
}

impl FromIterator<PeerId> for StaticAllowlist {
    fn from_iter<I: IntoIterator<Item = PeerId>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl PeerAllowlist for StaticAllowlist {
    fn is_authorized(&self, peer: &PeerId) -> bool {
        self.0.contains(peer)
    }
}

/// Ceiling applied to any peer-supplied `timeout_ms` before it reaches the
/// kernel (5 minutes), mirroring the daemon's local `plugins/invoke` clamp.
///
/// A remote caller must not be able to pin a worker indefinitely.
pub const MAX_REMOTE_TASK_TIMEOUT_MS: u64 = 5 * 60 * 1_000;

/// The server half: executes tasks on the local kernel for authorized peers.
///
/// Clone is cheap; one instance serves every inbound connection.
#[derive(Clone)]
pub struct RemoteTaskServer {
    kernel: Arc<Kernel>,
    allowlist: Arc<dyn PeerAllowlist>,
    local_peer_id: PeerId,
    max_timeout_ms: u64,
    max_input_bytes: u64,
    max_output_bytes: u64,
}

impl std::fmt::Debug for RemoteTaskServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteTaskServer")
            .field("local_peer_id", &self.local_peer_id)
            .field("allowlist", &self.allowlist)
            .field("max_timeout_ms", &self.max_timeout_ms)
            .field("max_input_bytes", &self.max_input_bytes)
            .field("max_output_bytes", &self.max_output_bytes)
            .finish()
    }
}

impl RemoteTaskServer {
    /// Serve `kernel` to the peers `allowlist` authorizes.
    pub fn new(
        kernel: Arc<Kernel>,
        allowlist: Arc<dyn PeerAllowlist>,
        local_peer_id: PeerId,
    ) -> Self {
        Self {
            kernel,
            allowlist,
            local_peer_id,
            max_timeout_ms: MAX_REMOTE_TASK_TIMEOUT_MS,
            max_input_bytes: OneShotTask::DEFAULT_MAX_INPUT_BYTES,
            max_output_bytes: OneShotTask::DEFAULT_MAX_OUTPUT_BYTES,
        }
    }

    /// Lower the timeout ceiling. Values above [`MAX_REMOTE_TASK_TIMEOUT_MS`]
    /// are clamped: a config cannot raise the ceiling, only lower it.
    #[must_use]
    pub fn with_max_timeout_ms(mut self, ms: u64) -> Self {
        self.max_timeout_ms = ms.min(MAX_REMOTE_TASK_TIMEOUT_MS);
        self
    }

    /// Lower the input/output size ceilings. Values above the spec defaults
    /// are clamped down for the same reason.
    #[must_use]
    pub fn with_max_bytes(mut self, input: u64, output: u64) -> Self {
        self.max_input_bytes = input.min(OneShotTask::DEFAULT_MAX_INPUT_BYTES);
        self.max_output_bytes = output.min(OneShotTask::DEFAULT_MAX_OUTPUT_BYTES);
        self
    }

    /// The timeout this node would actually apply to a peer that asked for
    /// `requested_ms`.
    ///
    /// This is the exact expression [`RemoteTaskServer::handle`] uses, exposed
    /// so the clamp can be asserted directly rather than inferred from timing.
    pub const fn effective_timeout_ms(&self, requested_ms: u64) -> u64 {
        if requested_ms < self.max_timeout_ms {
            requested_ms
        } else {
            self.max_timeout_ms
        }
    }

    /// The output ceiling this node would actually apply to a peer that
    /// declared `requested_max`.
    pub const fn effective_output_cap(&self, requested_max: u64) -> u64 {
        if requested_max < self.max_output_bytes {
            requested_max
        } else {
            self.max_output_bytes
        }
    }

    /// The input ceiling this node enforces, whatever a peer declares.
    pub const fn input_ceiling(&self) -> u64 {
        self.max_input_bytes
    }

    /// Handle one inbound frame from `from`, returning the frame to send back.
    ///
    /// Never panics and never returns `Err`: a caller waiting on a response
    /// must always get one, so every failure is encoded as a structured
    /// [`RemoteOutcome::Err`].
    pub async fn handle(&self, from: PeerId, payload: Vec<u8>) -> Vec<u8> {
        let response = self.respond(from, payload).await;
        encode_response(&response).unwrap_or_else(|e| {
            // The only realistic cause is an output that fits the task's
            // limits but not a single frame. Answer with an error that does
            // fit, so the caller sees a typed failure instead of a dead
            // connection.
            tracing::warn!(peer = %from, error = %e, "scheduler: response did not fit a frame");
            encode_response(&RemoteTaskResponse::err(
                RemoteErrorCode::OutputTooLarge,
                "response too large to transmit as a single frame",
            ))
            .unwrap_or_default()
        })
    }

    /// The decision logic behind [`RemoteTaskServer::handle`].
    async fn respond(&self, from: PeerId, payload: Vec<u8>) -> RemoteTaskResponse {
        // ── THE SECURITY GATE ────────────────────────────────────────────
        // `from` is the identity QUIC authenticated during the handshake.
        // Check it before decoding: an unauthorized peer must not even get
        // this node's parser as an attack surface, let alone its kernel.
        if !self.allowlist.is_authorized(&from) {
            tracing::warn!(
                peer = %from,
                "scheduler: refused task from a peer that is not in the trusted allowlist"
            );
            return RemoteTaskResponse::err(
                RemoteErrorCode::NotAuthorized,
                "peer is not in this node's trusted peer allowlist",
            );
        }

        let request = match decode_request(&payload) {
            Ok(req) => req,
            Err(e) => {
                let code = match e {
                    WireError::UnsupportedVersion { .. } => RemoteErrorCode::UnsupportedVersion,
                    WireError::InputTooLarge { .. } => RemoteErrorCode::InputTooLarge,
                    WireError::FrameTooLarge { .. } => RemoteErrorCode::InputTooLarge,
                    WireError::Malformed(_) | WireError::OutputTooLarge { .. } => {
                        RemoteErrorCode::MalformedRequest
                    }
                };
                tracing::debug!(peer = %from, error = %e, "scheduler: rejected request envelope");
                return RemoteTaskResponse::err(code, e.to_string());
            }
        };

        // The caller's own declared ceiling was already enforced by
        // `decode_request`; this is *this node's* ceiling, which the caller
        // cannot raise.
        let input_len = request.input.len() as u64;
        if input_len > self.max_input_bytes {
            return RemoteTaskResponse::err(
                RemoteErrorCode::InputTooLarge,
                format!(
                    "input of {input_len} bytes exceeds this node's {} byte limit",
                    self.max_input_bytes
                ),
            );
        }

        let plugin: PluginId = match request.plugin.parse() {
            Ok(id) => id,
            Err(e) => {
                return RemoteTaskResponse::err(
                    RemoteErrorCode::MalformedRequest,
                    format!("plugin id {:?}: {e}", request.plugin),
                )
            }
        };

        // Clamp the peer-supplied timeout. Untrusted input: without this a
        // caller could pin a worker for as long as it liked.
        let timeout_ms = self.effective_timeout_ms(request.timeout_ms);
        let output_cap = self.effective_output_cap(request.max_output_bytes);

        let task = OneShotTask {
            id: uuid::Uuid::from_bytes(request.task_id),
            plugin,
            input: request.input,
            max_input_bytes: self.max_input_bytes,
            max_output_bytes: output_cap,
            resources: ResourceSpec::default(),
            // Always exactly one execution. The caller's integrity policy is
            // *its* verification concern; honouring a peer-named policy here
            // would let one frame request N executions.
            integrity: IntegrityPolicy::None,
            timeout_ms,
        };

        tracing::info!(
            peer = %from,
            plugin = %task.plugin,
            input_bytes = input_len,
            timeout_ms,
            "scheduler: executing task for remote peer"
        );

        match self
            .kernel
            .invoke_with_integrity(&task, self.local_peer_id)
            .await
        {
            Ok(output) => {
                let actual = output.len() as u64;
                if actual > output_cap {
                    return RemoteTaskResponse::err(
                        RemoteErrorCode::OutputTooLarge,
                        format!("output of {actual} bytes exceeds the {output_cap} byte limit"),
                    );
                }
                RemoteTaskResponse::ok(output)
            }
            Err(RuntimeError::NotLoaded(id)) => RemoteTaskResponse::err(
                RemoteErrorCode::PluginNotLoaded,
                format!("plugin {id} is not loaded on this node"),
            ),
            Err(e) => {
                tracing::warn!(peer = %from, error = %e, "scheduler: remote task failed");
                RemoteTaskResponse::err(RemoteErrorCode::Execution, e.to_string())
            }
        }
    }
}

/// Serve scheduler task requests on `transport` until it is shut down.
///
/// `transport` must have been started with
/// [`ALPN_SCHEDULER`](entangle_mesh_iroh::ALPN_SCHEDULER); peers speaking any
/// other ALPN are refused by the transport before reaching this loop.
///
/// Intended to be spawned:
///
/// ```no_run
/// # use std::sync::Arc;
/// # async fn demo(
/// #     transport: Arc<entangle_mesh_iroh::MeshIroh>,
/// #     server: Arc<entangle_scheduler::remote::RemoteTaskServer>,
/// # ) {
/// tokio::spawn(entangle_scheduler::remote::serve_tasks(transport, server));
/// # }
/// ```
pub async fn serve_tasks(transport: Arc<MeshIroh>, server: Arc<RemoteTaskServer>) {
    entangle_mesh_iroh::serve(transport, move |peer, bytes| {
        let server = Arc::clone(&server);
        async move { server.handle(peer, bytes).await }
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(byte: u8) -> PeerId {
        PeerId::from_public_key_bytes(&[byte; 32])
    }

    #[test]
    fn empty_allowlist_authorizes_nobody() {
        let allow = StaticAllowlist::new();
        assert!(!allow.is_authorized(&peer(1)));
        assert!(!allow.is_authorized(&peer(2)));
    }

    #[test]
    fn allowlist_admits_only_named_peers() {
        let allow = StaticAllowlist::new().allow(peer(1));
        assert!(allow.is_authorized(&peer(1)));
        assert!(!allow.is_authorized(&peer(2)));
    }

    #[test]
    fn directory_round_trips_and_forgets() {
        let dir = PeerDirectory::new();
        assert!(dir.is_empty());
        assert_eq!(dir.lookup(&peer(3)), None);

        let entry = IrohPeer::new([3u8; 32], "127.0.0.1:9".parse().expect("addr"));
        dir.insert(entry.clone());
        assert_eq!(dir.len(), 1);
        assert_eq!(dir.lookup(&entry.peer_id), Some(entry.clone()));

        assert_eq!(dir.remove(&entry.peer_id), Some(entry.clone()));
        assert_eq!(dir.lookup(&entry.peer_id), None);
    }

    /// A directory keyed by a peer id must not answer for a *different* id
    /// that happens to share an address.
    #[test]
    fn directory_lookup_is_keyed_by_identity() {
        let dir = PeerDirectory::new();
        let addr = "127.0.0.1:9".parse().expect("addr");
        dir.insert(IrohPeer::new([4u8; 32], addr));
        assert!(dir.lookup(&peer(5)).is_none());
    }

    /// A config must never be able to raise the hard ceilings.
    #[test]
    fn ceilings_clamp_downward_only() {
        let kernel = Arc::new(
            Kernel::new(
                entangle_runtime::KernelConfig::default(),
                entangle_signing::Keyring::new(),
            )
            .expect("kernel"),
        );
        let server = RemoteTaskServer::new(kernel, Arc::new(StaticAllowlist::new()), peer(0))
            .with_max_timeout_ms(u64::MAX)
            .with_max_bytes(u64::MAX, u64::MAX);
        assert_eq!(server.max_timeout_ms, MAX_REMOTE_TASK_TIMEOUT_MS);
        assert_eq!(server.max_input_bytes, OneShotTask::DEFAULT_MAX_INPUT_BYTES);
        assert_eq!(
            server.max_output_bytes,
            OneShotTask::DEFAULT_MAX_OUTPUT_BYTES
        );

        let lowered = RemoteTaskServer::new(
            Arc::new(
                Kernel::new(
                    entangle_runtime::KernelConfig::default(),
                    entangle_signing::Keyring::new(),
                )
                .expect("kernel"),
            ),
            Arc::new(StaticAllowlist::new()),
            peer(0),
        )
        .with_max_timeout_ms(250)
        .with_max_bytes(64, 128);
        assert_eq!(lowered.max_timeout_ms, 250, "lowering must be honoured");
        assert_eq!(lowered.max_input_bytes, 64);
        assert_eq!(lowered.max_output_bytes, 128);
    }
}
