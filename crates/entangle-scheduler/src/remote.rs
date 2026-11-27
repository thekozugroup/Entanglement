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
use entangle_runtime::{check_trusted_executor, IntegrityError, Kernel, RuntimeError};
use entangle_types::peer_id::PeerId;
use entangle_types::plugin_id::PluginId;
use entangle_types::resource::ResourceSpec;
use entangle_types::task::{IntegrityPolicy, OneShotTask};
use parking_lot::RwLock;

use crate::dispatcher::DispatchError;
use crate::worker::{WorkerCapabilities, WorkerInfo};

const MAX_CAPABILITIES_BYTES: usize = 256 * 1024;

// A leading zero is disjoint from every valid v1 task. Match the entire frame.
const CAPABILITIES_REQUEST: &[u8] = b"\0entangle/worker-capabilities/1";
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
#[async_trait::async_trait]
pub trait PeerAddressBook: std::fmt::Debug + Send + Sync {
    /// The peer's current dialable descriptor, or `None` if unknown.
    fn lookup(&self, peer: &PeerId) -> Option<IrohPeer>;

    /// Look up a selected one-shot worker and indicate whether a missing
    /// route can be refreshed. Called on a blocking worker, like `lookup`.
    fn lookup_for_dispatch(&self, peer: &PeerId) -> (Option<IrohPeer>, bool) {
        (self.lookup(peer), false)
    }

    /// Wait briefly for an address update following an eligible dispatch miss.
    /// The caller must look up the peer again and check its identity, since a
    /// concurrent refresh may finish before this waiter attaches.
    async fn refresh_missing_route(&self) {}

    /// Check current authority for an established worker stream. Persisted trust
    /// implementations may authorize the identity independently of address churn.
    fn permits_stream(&self, peer: &PeerId) -> bool {
        self.lookup(peer).is_some_and(|addr| {
            addr.peer_id == *peer && PeerId::from_public_key_bytes(&addr.public_key) == *peer
        })
    }
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
    signer: Option<Arc<entangle_signing::IdentityKeyPair>>,
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
    /// Resolve a paired peer and establish an identity-checked connection for a relay frame.
    pub async fn connect_relay(
        &self,
        peer: PeerId,
    ) -> Result<entangle_mesh_iroh::MeshConn, DispatchError> {
        let addr = self.address(peer).await?;
        self.transport
            .connect(&addr)
            .await
            .map_err(|e| DispatchError::RemoteTransport {
                peer,
                reason: e.to_string(),
            })
    }

    /// Start a duplex streaming invocation on an explicitly selected trusted worker.
    pub async fn open_stream(
        &self,
        peer: PeerId,
        task: entangle_types::task::StreamingTask,
        input: &[u8],
    ) -> Result<crate::stream::StreamingClient, crate::stream::StreamError> {
        crate::stream::validate(&task, input.len(), Some(peer))?;
        let addr = self
            .address(peer)
            .await
            .map_err(|e| crate::stream::StreamError::Invalid(e.to_string()))?;
        let conn = self.transport.connect(&addr).await?;
        if conn.remote_peer_id() != peer {
            return Err(crate::stream::StreamError::BadChunkSignature);
        }
        crate::stream::StreamingClient::start(conn, task, input, self.addresses.clone()).await
    }

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
            signer: None,
        }
    }

    /// Use the daemon identity to sign integrity-protected replica work units.
    #[must_use]
    pub fn with_signer(mut self, signer: entangle_signing::IdentityKeyPair) -> Self {
        self.signer = Some(Arc::new(signer));
        self
    }

    pub(crate) fn signed_request(
        &self,
        task: &OneShotTask,
        policy: crate::work_unit::Policy,
    ) -> Result<([u8; 32], Vec<u8>), DispatchError> {
        let signer = self.signer.as_deref().ok_or_else(|| {
            DispatchError::Integrity("submitter signing identity unavailable".into())
        })?;
        let request = encode_request(&RemoteTaskRequest::for_task(task))
            .map_err(|e| DispatchError::Integrity(e.to_string()))?;
        crate::work_unit::encode(signer, &request, policy).map_err(DispatchError::Integrity)
    }

    pub(crate) async fn negotiate_signed(&self, peer: PeerId) -> Result<IrohPeer, DispatchError> {
        use crate::work_unit::PROBE;
        let addr = self.address(peer).await?;
        let failure = |reason: String| DispatchError::RemoteTransport { peer, reason };
        let raw = self
            .transport
            .request(&addr, PROBE)
            .await
            .map_err(|e| failure(e.to_string()))?;
        match decode_response(&raw, PROBE.len() as u64)
            .map_err(|e| failure(e.to_string()))?
            .outcome
        {
            RemoteOutcome::Ok { output } if output == PROBE => Ok(addr),
            RemoteOutcome::Err { code, message } => Err(DispatchError::RemoteRejected {
                peer,
                code,
                message,
            }),
            _ => Err(failure(
                "worker does not support signed semantic replicas".into(),
            )),
        }
    }

    pub(crate) async fn signed_replica(
        &self,
        task: &OneShotTask,
        addr: &IrohPeer,
        hash: &[u8; 32],
        frame: &[u8],
    ) -> Result<Vec<u8>, DispatchError> {
        use crate::work_unit::{check_receipt, BorrowedOutcome, RECEIPT_LEN};
        let peer = addr.peer_id;
        let failure = |reason: String| DispatchError::RemoteTransport { peer, reason };
        let raw = self
            .transport
            .request(addr, frame)
            .await
            .map_err(|e| failure(e.to_string()))?;
        let (_, outcome): (u16, BorrowedOutcome<'_>) =
            crate::wire::decode(&raw).map_err(|e| failure(e.to_string()))?;
        match outcome {
            BorrowedOutcome::Ok { output } => {
                if !check_receipt(output, task.id.as_bytes(), hash) {
                    return Err(DispatchError::Integrity(
                        "PolicyMutation: replica receipt does not match submitted policy and task"
                            .into(),
                    ));
                }
                let data = &output[RECEIPT_LEN..];
                let actual = data.len() as u64;
                if actual > task.max_output_bytes {
                    return Err(DispatchError::OutputSizeExceeded(
                        entangle_types::errors::EntangleError::OutputSizeExceeded {
                            declared: task.max_output_bytes,
                            actual,
                            peer: peer.to_hex(),
                        },
                    ));
                }
                Ok(data.to_vec())
            }
            BorrowedOutcome::Err { code, message } => Err(DispatchError::RemoteRejected {
                peer,
                code,
                message: message.to_owned(),
            }),
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

    async fn lookup_address(
        &self,
        peer: PeerId,
        check_refresh: bool,
    ) -> Result<(Option<IrohPeer>, bool), DispatchError> {
        let addresses = self.addresses.clone();
        let (addr, refresh) = tokio::task::spawn_blocking(move || {
            if check_refresh {
                addresses.lookup_for_dispatch(&peer)
            } else {
                (addresses.lookup(&peer), false)
            }
        })
        .await
        .map_err(|err| DispatchError::RemoteTransport {
            peer,
            reason: err.to_string(),
        })?;

        // QUIC authenticates the descriptor's public key. Bind that key to
        // the peer whose eligibility placement and the integrity policy checked.
        if addr.as_ref().is_some_and(|addr| {
            addr.peer_id != peer || PeerId::from_public_key_bytes(&addr.public_key) != peer
        }) {
            return Err(DispatchError::RemoteTransport {
                peer,
                reason: "address book returned a different peer identity".into(),
            });
        }

        Ok((addr, refresh))
    }

    fn missing_address(peer: PeerId) -> DispatchError {
        DispatchError::RemoteTransport {
            peer,
            reason:
                "no known network address for this peer (not paired, or no address learned yet)"
                    .to_owned(),
        }
    }

    async fn address(&self, peer: PeerId) -> Result<IrohPeer, DispatchError> {
        self.lookup_address(peer, false)
            .await?
            .0
            .ok_or_else(|| Self::missing_address(peer))
    }

    /// Read this trusted worker's hardware advertisement over identity-bound QUIC.
    /// The RTT includes connection setup. Peers implementing only task wire v1
    /// answer this extension with an unsupported-version error.
    pub async fn capabilities(&self, peer: PeerId) -> Result<WorkerCapabilities, DispatchError> {
        let addr = self.address(peer).await?;
        let invalid = |reason: String| DispatchError::RemoteTransport { peer, reason };
        let start = std::time::Instant::now();
        let raw = tokio::time::timeout(
            Duration::from_secs(5),
            self.transport.request(&addr, CAPABILITIES_REQUEST),
        )
        .await
        .map_err(|_| invalid("capability request timed out".into()))?
        .map_err(|e| invalid(e.to_string()))?;
        if raw.len() > MAX_CAPABILITIES_BYTES + 32 {
            return Err(invalid("oversized capability response".into()));
        }
        let response = decode_response(&raw, MAX_CAPABILITIES_BYTES as u64)
            .map_err(|e| invalid(e.to_string()))?;
        let bytes = match response.outcome {
            RemoteOutcome::Ok { output } => output,
            RemoteOutcome::Err { code, message } => {
                return Err(DispatchError::RemoteRejected {
                    peer,
                    code,
                    message,
                })
            }
        };
        let mut report: WorkerCapabilities =
            serde_json::from_slice(&bytes).map_err(|e| invalid(e.to_string()))?;
        if report.worker.peer_id != peer {
            return Err(invalid(
                "capability report identifies a different peer".into(),
            ));
        }
        report
            .worker
            .validate()
            .map_err(|e| invalid(e.to_string()))?;
        report.worker.rtt_ms = start.elapsed().as_millis().min(u32::MAX.into()) as u32;
        Ok(report)
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
        self.dispatch_measured(task, peer)
            .await
            .map(|(bytes, _)| bytes)
    }

    pub(crate) async fn dispatch_measured(
        &self,
        task: &OneShotTask,
        peer: PeerId,
    ) -> Result<(Vec<u8>, Option<u64>), DispatchError> {
        // The wire request asks for exactly one execution. Verify the caller's
        // policy before sharing its input, including for direct client calls.
        let unsupported = match &task.integrity {
            IntegrityPolicy::TrustedExecutor { .. } => {
                check_trusted_executor(&task.integrity, &peer).map_err(RuntimeError::from)?;
                None
            }
            IntegrityPolicy::None | IntegrityPolicy::Deterministic { replicas: 0 | 1 } => None,
            IntegrityPolicy::Deterministic { .. } => {
                Some("remote Deterministic with multiple replicas")
            }
            IntegrityPolicy::SemanticEquivalent { .. } => Some("SemanticEquivalent"),
            IntegrityPolicy::Attested { .. } => Some("Attested"),
        };
        if let Some(policy) = unsupported {
            return Err(RuntimeError::Integrity(IntegrityError::NotImplemented(policy)).into());
        }

        let budget = Duration::from_millis(task.timeout_ms).saturating_add(self.overhead);
        let route_timeout = || DispatchError::RemoteTransport {
            peer,
            reason: "deadline exceeded while refreshing the peer network address".into(),
        };
        let (mut addr, refresh) = self.lookup_address(peer, true).await?;
        let refresh_started = if addr.is_none() && refresh {
            if budget.is_zero() {
                return Err(route_timeout());
            }
            let started = tokio::time::Instant::now();
            let wait = async {
                self.addresses.refresh_missing_route().await;
                self.address(peer).await
            };
            addr = Some(
                tokio::time::timeout(budget, wait)
                    .await
                    .map_err(|_| route_timeout())??,
            );
            Some(started)
        } else {
            None
        };
        let addr = addr.ok_or_else(|| Self::missing_address(peer))?;
        let request = RemoteTaskRequest::for_task(task);
        let frame = encode_request(&request).map_err(|e| DispatchError::RemoteTransport {
            peer,
            reason: format!("encoding request: {e}"),
        })?;

        let transfer = async {
            // Tokio's timeout polls the future before checking its deadline.
            if refresh_started.is_some_and(|started| started.elapsed() >= budget) {
                return Err(route_timeout());
            }
            let result = if task.input.len() >= crate::placement::MIN_UPLOAD_BYTES {
                self.transport.request_with_upload(&addr, &frame).await
            } else {
                self.transport
                    .request(&addr, &frame)
                    .await
                    .map(|raw| (raw, None))
            };
            result.map_err(|error| DispatchError::RemoteTransport {
                peer,
                reason: error.to_string(),
            })
        };
        let remaining =
            refresh_started.map_or(budget, |started| budget.saturating_sub(started.elapsed()));
        let (raw, upload) = tokio::time::timeout(remaining, transfer)
            .await
            .map_err(|_| DispatchError::RemoteTransport {
                peer,
                reason: format!(
                    "no answer before the {}ms transfer deadline (task timeout {}ms + {}ms overhead, including any route refresh)",
                    budget.as_millis(),
                    task.timeout_ms,
                    self.overhead.as_millis()
                ),
            })??;

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
            RemoteOutcome::Ok { output } => Ok((output, upload)),
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
    relay_handler: Option<Arc<dyn crate::relay::RelayHandler>>,
    streaming: Option<(
        Arc<entangle_signing::IdentityKeyPair>,
        Arc<dyn crate::stream::StreamExecutor>,
    )>,
    stream_slots: Arc<tokio::sync::Semaphore>,
    capabilities: Option<WorkerInfo>,
    active: Arc<crate::work_unit::Active>,
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
            capabilities: None,
            relay_handler: None,
            streaming: None,
            stream_slots: Arc::new(tokio::sync::Semaphore::new(32)),
            active: Arc::default(),
            kernel,
            allowlist,
            local_peer_id,
            max_timeout_ms: MAX_REMOTE_TASK_TIMEOUT_MS,
            max_input_bytes: OneShotTask::DEFAULT_MAX_INPUT_BYTES,
            max_output_bytes: OneShotTask::DEFAULT_MAX_OUTPUT_BYTES,
        }
    }

    /// Enable the operator-configured endpoint/forwarder for signed relay frames.
    pub fn with_relay_handler(
        mut self,
        handler: Option<Arc<dyn crate::relay::RelayHandler>>,
    ) -> Self {
        self.relay_handler = handler;
        self
    }

    /// Enable signed duplex streams with the local identity and a bounded producer.
    pub fn with_stream_executor(
        mut self,
        identity: entangle_signing::IdentityKeyPair,
        executor: Arc<dyn crate::stream::StreamExecutor>,
    ) -> Self {
        self.streaming = Some((Arc::new(identity), executor));
        self
    }

    /// Advertise this worker to authorized peers that request its capabilities.
    pub fn with_capabilities(mut self, capabilities: WorkerInfo) -> Self {
        self.capabilities = Some(capabilities);
        self
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
        let allowlist = self.allowlist.clone();
        let authorized = tokio::task::spawn_blocking(move || allowlist.is_authorized(&from))
            .await
            .unwrap_or(false);
        if !authorized {
            tracing::warn!(
                peer = %from,
                "scheduler: refused task from a peer that is not in the trusted allowlist"
            );
            return RemoteTaskResponse::err(
                RemoteErrorCode::NotAuthorized,
                "peer is not in this node's trusted peer allowlist",
            );
        }

        if payload == crate::work_unit::PROBE {
            return RemoteTaskResponse::ok(crate::work_unit::PROBE.to_vec());
        }
        if payload.starts_with(crate::work_unit::MUTATE) {
            return crate::work_unit::mutation();
        }
        if let Some(bytes) = payload.strip_prefix(crate::work_unit::WORK) {
            let (request, lease) = match self.active.accept(from, bytes) {
                Ok(work) => work,
                Err(e) => return e,
            };
            let response = self.execute(from, request).await;
            return match response.outcome {
                RemoteOutcome::Ok { output } => match lease.complete(&output) {
                    Ok(receipt) => RemoteTaskResponse::ok(receipt),
                    Err(e) => e,
                },
                _ => response,
            };
        }
        if payload == CAPABILITIES_REQUEST {
            let (plugins, mut streaming_plugins) = self.kernel.execution_plugins();
            if let (Some((_, executor)), Some(_)) = (&self.streaming, &self.capabilities) {
                streaming_plugins.extend(executor.streaming_plugins().await);
            } else {
                streaming_plugins.clear();
            }
            return match &self.capabilities {
                Some(worker) => match serde_json::to_vec(&WorkerCapabilities {
                    worker: worker.clone(),
                    plugins,
                    streaming_plugins,
                }) {
                    Ok(bytes) if bytes.len() <= MAX_CAPABILITIES_BYTES => {
                        RemoteTaskResponse::ok(bytes)
                    }
                    Ok(_) => RemoteTaskResponse::err(
                        RemoteErrorCode::OutputTooLarge,
                        "capability inventory too large",
                    ),
                    Err(_) => RemoteTaskResponse::err(
                        RemoteErrorCode::Internal,
                        "invalid local capabilities",
                    ),
                },
                None => RemoteTaskResponse::err(
                    RemoteErrorCode::UnsupportedVersion,
                    "worker capabilities unavailable",
                ),
            };
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

        self.execute(from, request).await
    }

    async fn execute(&self, from: PeerId, request: RemoteTaskRequest) -> RemoteTaskResponse {
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
            Err(e) if e.is_libtest_identity_mismatch() => {
                RemoteTaskResponse::err(RemoteErrorCode::SuiteIdentityMismatch, e.to_string())
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
    entangle_mesh_iroh::serve_requests(transport, move |mut req| {
        let server = server.clone();
        async move {
            let peer = req.peer_id();
            if req.payload().starts_with(crate::relay::PREFIX) {
                let Some(handler) = &server.relay_handler else {
                    return req.respond(br#"{"Err":"relay disabled"}"#).await;
                };
                let allow = server.allowlist.clone();
                if !tokio::task::spawn_blocking(move || allow.is_authorized(&peer))
                    .await
                    .unwrap_or(false)
                {
                    return req.respond(br#"{"Err":"not-authorized"}"#).await;
                }
                let Ok(_slot) = server.stream_slots.try_acquire() else {
                    return req.respond(br#"{"Err":"worker busy"}"#).await;
                };
                let response = handler
                    .handle(peer, req.selected_socket(), req.take_payload())
                    .await;
                return req.respond(&response).await;
            }
            if req.payload().starts_with(crate::stream::OPEN) {
                let list = server.allowlist.clone();
                let authorized = tokio::task::spawn_blocking(move || list.is_authorized(&peer))
                    .await
                    .unwrap_or(false);
                let failure = |reason: &[u8]| {
                    let mut v = vec![8u8];
                    v.extend_from_slice(reason);
                    v
                };
                if !authorized {
                    return req.respond(&failure(b"not-authorized")).await;
                }
                let Some((signer, executor)) = &server.streaming else {
                    return req.respond(&failure(b"streaming disabled")).await;
                };
                let Ok(_slot) = server.stream_slots.try_acquire() else {
                    return req.respond(&failure(b"worker busy")).await;
                };
                return crate::stream::serve_worker(
                    req,
                    signer.clone(),
                    executor.clone(),
                    server.local_peer_id,
                    server.allowlist.clone(),
                    &server.kernel,
                    server.max_timeout_ms,
                )
                .await;
            }
            let response = server.handle(peer, req.take_payload()).await;
            req.respond(&response).await
        }
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use entangle_mesh_iroh::{MeshConn, MeshIrohError, MeshTransport};
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::sync::Notify;

    fn peer(byte: u8) -> PeerId {
        PeerId::from_public_key_bytes(&[byte; 32])
    }

    #[derive(Debug)]
    struct RefreshableRoute {
        hint: IrohPeer,
        paired: AtomicBool,
        learned: AtomicBool,
        starting: Notify,
        finish: Notify,
        refreshes: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl PeerAddressBook for RefreshableRoute {
        fn lookup(&self, peer: &PeerId) -> Option<IrohPeer> {
            (*peer == self.hint.peer_id
                && self.paired.load(Ordering::Relaxed)
                && self.learned.load(Ordering::Relaxed))
            .then(|| self.hint.clone())
        }

        fn lookup_for_dispatch(&self, peer: &PeerId) -> (Option<IrohPeer>, bool) {
            let hint = self.lookup(peer);
            let refresh =
                hint.is_none() && *peer == self.hint.peer_id && self.paired.load(Ordering::Relaxed);
            (hint, refresh)
        }

        async fn refresh_missing_route(&self) {
            self.refreshes.fetch_add(1, Ordering::Relaxed);
            self.starting.notify_one();
            self.finish.notified().await;
        }
    }

    #[derive(Debug, Default)]
    struct CountDispatches {
        requests: AtomicUsize,
        reject: AtomicBool,
    }

    #[async_trait::async_trait]
    impl MeshTransport for CountDispatches {
        fn local_peer_id(&self) -> PeerId {
            peer(0)
        }
        fn local_public_key(&self) -> [u8; 32] {
            [0; 32]
        }
        fn local_addrs(&self) -> Vec<SocketAddr> {
            vec![]
        }
        async fn connect(&self, _: &IrohPeer) -> Result<MeshConn, MeshIrohError> {
            unreachable!("test accepts only one-shot task requests")
        }
        async fn accept(&self) -> Result<Option<MeshConn>, MeshIrohError> {
            Ok(None)
        }
        async fn request(&self, worker: &IrohPeer, wire: &[u8]) -> Result<Vec<u8>, MeshIrohError> {
            assert_eq!(worker.peer_id, peer(1));
            let task = decode_request(wire).expect("encoded one-shot task");
            assert_eq!(task.input, b"one invocation");
            self.requests.fetch_add(1, Ordering::Relaxed);
            let response = if self.reject.load(Ordering::Relaxed) {
                RemoteTaskResponse::err(RemoteErrorCode::Execution, "fixture rejected the task")
            } else {
                RemoteTaskResponse::ok(b"executed".to_vec())
            };
            Ok(encode_response(&response).unwrap())
        }
        async fn shutdown(&self) {}
    }

    #[tokio::test]
    async fn only_one_shot_route_misses_refresh_and_pairing_is_rechecked() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let worker = peer(1);
            let routes = Arc::new(RefreshableRoute {
                hint: IrohPeer::new([1; 32], "100.64.0.2:7443".parse().unwrap()),
                paired: AtomicBool::new(true),
                learned: AtomicBool::new(false),
                starting: Notify::new(),
                finish: Notify::new(),
                refreshes: AtomicUsize::new(0),
            });
            let transport = Arc::new(CountDispatches::default());
            let client = RemoteDispatch::new(transport.clone(), routes.clone())
                .with_overhead(Duration::ZERO);
            let mut task = OneShotTask::with_defaults(
                "0123456789abcdef0123456789abcdef/fixture@0.1.0"
                    .parse()
                    .unwrap(),
                b"one invocation".to_vec(),
            );
            assert!(client.capabilities(worker).await.is_err());
            assert_eq!(routes.refreshes.load(Ordering::Relaxed), 0);

            task.integrity = IntegrityPolicy::TrustedExecutor {
                allowlist: vec![peer(2)],
            };
            assert!(client.dispatch(&task, worker).await.is_err());
            assert_eq!(routes.refreshes.load(Ordering::Relaxed), 0);
            task.integrity = IntegrityPolicy::TrustedExecutor {
                allowlist: vec![worker],
            };
            task.timeout_ms = 1000;
            let first = client.dispatch(&task, worker);
            tokio::pin!(first);
            tokio::select! {
                _ = routes.starting.notified() => {},
                result = &mut first => panic!("dispatch finished before refresh: {result:?}"),
            }
            assert_eq!(transport.requests.load(Ordering::Relaxed), 0);
            // Another request can publish while this caller is waiting. Always
            // look again, even when this caller got no explicit completion.
            routes.learned.store(true, Ordering::Relaxed);
            routes.finish.notify_one();
            assert_eq!(first.await.unwrap(), b"executed");
            assert_eq!(client.dispatch(&task, worker).await.unwrap(), b"executed");
            assert_eq!(routes.refreshes.load(Ordering::Relaxed), 1);
            assert_eq!(transport.requests.load(Ordering::Relaxed), 2);
            transport.reject.store(true, Ordering::Relaxed);
            assert!(matches!(
                client.dispatch(&task, worker).await,
                Err(DispatchError::RemoteRejected {
                    code: RemoteErrorCode::Execution,
                    ..
                })
            ));
            assert_eq!(routes.refreshes.load(Ordering::Relaxed), 1);
            assert_eq!(transport.requests.load(Ordering::Relaxed), 3);

            routes.learned.store(false, Ordering::Relaxed);
            let revoked = client.dispatch(&task, worker);
            tokio::pin!(revoked);
            tokio::select! {
                _ = routes.starting.notified() => {},
                result = &mut revoked => panic!("dispatch finished before refresh: {result:?}"),
            }
            routes.paired.store(false, Ordering::Relaxed);
            routes.learned.store(true, Ordering::Relaxed);
            routes.finish.notify_one();
            assert!(revoked.await.is_err());
            assert!(client.dispatch(&task, worker).await.is_err());
            assert_eq!(routes.refreshes.load(Ordering::Relaxed), 2);
            assert_eq!(transport.requests.load(Ordering::Relaxed), 3);

            routes.paired.store(true, Ordering::Relaxed);
            routes.learned.store(false, Ordering::Relaxed);
            let mut bounded = task.clone();
            bounded.timeout_ms = 0;
            assert!(client.dispatch(&bounded, worker).await.is_err());
            assert_eq!(routes.refreshes.load(Ordering::Relaxed), 2);
            bounded.timeout_ms = 25;
            assert!(client.dispatch(&bounded, worker).await.is_err());
            assert_eq!(routes.refreshes.load(Ordering::Relaxed), 3);
            assert_eq!(transport.requests.load(Ordering::Relaxed), 3);
        })
        .await
        .expect("bounded test dispatches");
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
