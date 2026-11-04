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
//! # Integrity envelope (wire v2, INV-INT-1)
//!
//! A task frame carries the task's integrity policy as canonical bytes plus
//! `policy_hash` ([`crate::work_unit`]). The executor:
//!
//! 1. verifies `SHA-256(policy) == policy_hash` **before executing** — a
//!    mismatch is [`RemoteErrorCode::PolicyHashMismatch`] and nothing runs;
//! 2. records the task as in flight, keyed by the transport-authenticated
//!    caller and the task id (a second frame with the same id while the first
//!    runs is [`RemoteErrorCode::DuplicateTask`] — still one execution per
//!    frame, never two per id);
//! 3. refuses a `SemanticEquivalent` metric reference whose publisher key
//!    does not hash to its plugin id, then logs the policy (metric included)
//!    for audit only — it never loads or runs a metric (§7.5 Rules 2–3);
//! 4. re-verifies the hash before answering and echoes the hash it observed
//!    in [`RemoteOutcome::Ok`], which the caller checks.
//!
//! A [`ControlFrame`] that would change the policy of an in-flight task is
//! refused with [`RemoteErrorCode::PolicyMutation`]; the running task keeps
//! its original policy. Control frames pass the same allowlist gate as task
//! frames, can only address the sending peer's own tasks, and never execute
//! anything.
//!
//! [`ALPN_SCHEDULER`]: entangle_mesh_iroh::ALPN_SCHEDULER
//! [`MeshTransport`]: entangle_mesh_iroh::MeshTransport
//! [`IntegrityPolicy::None`]: entangle_types::task::IntegrityPolicy::None

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use entangle_mesh_iroh::{DynMeshTransport, IrohPeer, MeshIroh, MeshIrohError};
use entangle_runtime::{IntegrityError, Kernel, RuntimeError};
use entangle_types::peer_id::PeerId;
use entangle_types::plugin_id::PluginId;
use entangle_types::resource::ResourceSpec;
use entangle_types::task::{IntegrityPolicy, OneShotTask, TaskId};
use parking_lot::{Mutex, RwLock};
use tracing::Instrument as _;

use crate::dispatcher::DispatchError;
use crate::wire::{
    decode_request, decode_response, encode_request, encode_response, ControlAction, ControlFrame,
    RemoteErrorCode, RemoteOutcome, RemoteRequest, RemoteTaskRequest, RemoteTaskResponse,
    RequestFrame, WireError,
};
use crate::work_unit::{hash_canonical, PolicyEnvelope, PolicyHash};

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
    /// Peers that answered a frame carrying a `traceparent` extension with
    /// `MalformedRequest` (a pre-extension build): we stop attaching it for
    /// them.
    no_trace_extension: Arc<Mutex<HashSet<PeerId>>>,
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
            no_trace_extension: Arc::default(),
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
    /// Seals the task's policy, dispatches it, and refuses an answer whose
    /// echoed policy hash differs from the one sent (`ENTANGLE-E0315`). The
    /// whole exchange is bounded by `task.timeout_ms` plus the configured
    /// overhead, so an unreachable or silent peer yields
    /// [`DispatchError::RemoteTransport`] rather than a hang.
    pub async fn dispatch(
        &self,
        task: &OneShotTask,
        peer: PeerId,
    ) -> Result<Vec<u8>, DispatchError> {
        let envelope = PolicyEnvelope::seal(&task.integrity)?;
        let replica = self.dispatch_sealed(task, peer, &envelope).await?;
        if replica.observed_policy_hash != envelope.hash() {
            return Err(IntegrityError::PolicyHashMismatch {
                peer: peer.to_hex(),
                expected: envelope.hash().to_hex(),
                observed: replica.observed_policy_hash.to_hex(),
            }
            .into());
        }
        Ok(replica.output)
    }

    /// Ship `task`, with its already-sealed policy `envelope`, to `peer`.
    ///
    /// Returns the output together with the policy hash the executor echoed;
    /// comparing that echo with `envelope.hash()` is the caller's job (the
    /// acceptance pipeline does it for every replica). An answer larger than
    /// `task.max_output_bytes` is refused while decoding, before its bytes
    /// are handed to anyone, as [`DispatchError::OutputSizeExceeded`] — also
    /// when trailing bytes follow it, and when the transport already refused
    /// its frame as over the transport cap (then `actual` is the declared
    /// frame length).
    pub async fn dispatch_sealed(
        &self,
        task: &OneShotTask,
        peer: PeerId,
        envelope: &PolicyEnvelope,
    ) -> Result<RemoteReplica, DispatchError> {
        let span = tracing::info_span!(
            "remote.dispatch",
            otel.kind = "client",
            peer = %peer,
            plugin = %task.plugin,
        );
        let response = self
            .dispatch_traced(task, peer, envelope)
            .instrument(span)
            .await?;
        match response.outcome {
            RemoteOutcome::Ok {
                output,
                observed_policy_hash,
            } => Ok(RemoteReplica {
                output,
                observed_policy_hash,
            }),
            RemoteOutcome::Ack { .. } => Err(DispatchError::RemoteTransport {
                peer,
                reason: "peer answered a task frame with a control acknowledgement".into(),
            }),
            RemoteOutcome::Err { code, message } => Err(DispatchError::RemoteRejected {
                peer,
                code,
                message,
            }),
        }
    }

    /// Send the task frame, carrying the current span's `traceparent` when a
    /// trace is being recorded and the peer is known to accept it.
    ///
    /// A peer built before the extension existed rejects such a frame as
    /// malformed; that one answer makes us resend the identical task without
    /// it and remember not to attach it for that peer again. (The rejected
    /// frame was refused at decode time, so nothing ran.)
    async fn dispatch_traced(
        &self,
        task: &OneShotTask,
        peer: PeerId,
        envelope: &PolicyEnvelope,
    ) -> Result<RemoteTaskResponse, DispatchError> {
        let budget = Duration::from_millis(task.timeout_ms).saturating_add(self.overhead);
        let traceparent = if self.no_trace_extension.lock().contains(&peer) {
            None
        } else {
            entangle_observability::context::current_traceparent()
        };
        let body = RemoteTaskRequest::sealed(task, envelope);
        let request = RemoteRequest::task(body.clone().with_traceparent(traceparent.clone()));
        let response = self
            .round_trip(peer, &request, budget, task.max_output_bytes)
            .await?;
        let rejected_extension = traceparent.is_some()
            && matches!(
                response.outcome,
                RemoteOutcome::Err {
                    code: RemoteErrorCode::MalformedRequest,
                    ..
                }
            );
        if !rejected_extension {
            return Ok(response);
        }
        tracing::debug!(%peer, "peer rejected the traceparent extension; resending without it");
        self.no_trace_extension.lock().insert(peer);
        self.round_trip(
            peer,
            &RemoteRequest::task(body),
            budget,
            task.max_output_bytes,
        )
        .await
    }

    /// Send a control frame about one of this node's in-flight tasks on
    /// `peer`, bounded by `timeout`.
    ///
    /// Returns the task's (unchanged) policy hash when the peer acknowledges.
    /// A policy-mutation attempt is refused by the peer and surfaces as
    /// [`IntegrityError::PolicyMutation`] (`ENTANGLE-E0316`); any other
    /// refusal as [`DispatchError::RemoteRejected`].
    pub async fn send_control(
        &self,
        peer: PeerId,
        frame: ControlFrame,
        timeout: Duration,
    ) -> Result<PolicyHash, DispatchError> {
        let task_id = TaskId::from_bytes(frame.task_id);
        let response = self
            .round_trip(peer, &RemoteRequest::control(frame), timeout, 0)
            .await?;
        match response.outcome {
            RemoteOutcome::Ack {
                observed_policy_hash,
                ..
            } => Ok(observed_policy_hash),
            RemoteOutcome::Err {
                code: RemoteErrorCode::PolicyMutation,
                ..
            } => Err(IntegrityError::PolicyMutation {
                peer: peer.to_hex(),
                task_id: task_id.to_string(),
            }
            .into()),
            RemoteOutcome::Err { code, message } => Err(DispatchError::RemoteRejected {
                peer,
                code,
                message,
            }),
            RemoteOutcome::Ok { .. } => Err(DispatchError::RemoteTransport {
                peer,
                reason: "peer answered a control frame with task output".into(),
            }),
        }
    }

    /// Encode, send, and decode one request under `budget`.
    async fn round_trip(
        &self,
        peer: PeerId,
        request: &RemoteRequest,
        budget: Duration,
        max_output_bytes: u64,
    ) -> Result<RemoteTaskResponse, DispatchError> {
        let addr = self
            .addresses
            .lookup(&peer)
            .ok_or_else(|| DispatchError::RemoteTransport {
                peer,
                reason: "no known network address for this peer (not paired, or no address \
                         learned yet)"
                    .to_owned(),
            })?;

        let frame = encode_request(request).map_err(|e| DispatchError::RemoteTransport {
            peer,
            reason: format!("encoding request: {e}"),
        })?;

        // INV-INT-2: a task answer bigger than the task's `max_output_bytes`
        // is an oversized output wherever it is caught — by the decoder, or
        // by the transport refusing its frame — so the acceptance pipeline
        // always warns and penalises. `actual` is then the frame length the
        // peer declared, an upper bound on its output.
        let is_task = matches!(request.frame, RequestFrame::Task(_));
        let oversized = |actual: u64| {
            DispatchError::OutputSizeExceeded(
                entangle_types::errors::EntangleError::OutputSizeExceeded {
                    declared: max_output_bytes,
                    actual,
                    peer: peer.to_hex(),
                },
            )
        };

        // The transport call runs on its own task so that it does not inherit
        // the caller's tracing span: the transport (iroh) creates long-lived
        // connection tasks and spans while dialling, and a child span that
        // outlives the request would keep this request's span — and every
        // ancestor — open, delaying its export until the connection ends.
        // The task is still owned by this call: it is aborted when the budget
        // runs out *and* when this future is dropped (a cancelled dispatch),
        // exactly as an inline `await` would have been.
        let io = {
            let transport = Arc::clone(&self.transport);
            let (addr, frame) = (addr.clone(), frame.clone());
            AbortOnDrop(tokio::spawn(async move {
                transport.request(&addr, &frame).await
            }))
        };
        let answer = match tokio::time::timeout(budget, io).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(join)) => {
                return Err(DispatchError::RemoteTransport {
                    peer,
                    reason: format!("transport task failed: {join}"),
                })
            }
            Err(elapsed) => Err(elapsed),
        };
        let raw = match answer {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => {
                // A frame-cap refusal is about the answer only when our own
                // request fit under that cap.
                if let MeshIrohError::FrameTooLarge { declared, max } = &e {
                    if is_task && frame.len() <= *max && *declared > max_output_bytes {
                        return Err(oversized(*declared));
                    }
                }
                return Err(DispatchError::RemoteTransport {
                    peer,
                    reason: e.to_string(),
                });
            }
            Err(_elapsed) => {
                return Err(DispatchError::RemoteTransport {
                    peer,
                    reason: format!(
                        "no answer within {}ms (request budget including {}ms overhead)",
                        budget.as_millis(),
                        self.overhead.as_millis()
                    ),
                })
            }
        };

        // The peer's answer is untrusted input: size-check it against *our*
        // limit, not anything it told us.
        decode_response(&raw, max_output_bytes).map_err(|e| match e {
            WireError::OutputTooLarge { actual, .. } => oversized(actual),
            // Over the wire cap (reachable only with a transport whose own
            // cap is larger) and over the task's limit: oversized too.
            WireError::FrameTooLarge { actual, .. }
                if is_task && actual as u64 > max_output_bytes =>
            {
                oversized(actual as u64)
            }
            other => DispatchError::RemoteTransport {
                peer,
                reason: other.to_string(),
            },
        })
    }
}

/// A spawned task that is aborted when this handle is dropped, so the task
/// cannot outlive the future that awaits it. (A plain `JoinHandle` detaches
/// its task on drop.)
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        // A no-op once the task has finished.
        self.0.abort();
    }
}

impl<T> std::future::Future for AbortOnDrop<T> {
    type Output = Result<T, tokio::task::JoinError>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::pin::Pin::new(&mut self.0).poll(cx)
    }
}

/// One remote replica's answer: output plus the policy hash the executor
/// echoed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteReplica {
    /// Raw output bytes.
    pub output: Vec<u8>,
    /// The policy hash the executor reported observing.
    pub observed_policy_hash: PolicyHash,
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

/// In-flight tasks on an executor: `(authenticated caller, task id)` → the
/// policy hash the task was accepted with.
type InFlight = Arc<Mutex<HashMap<(PeerId, [u8; 16]), PolicyHash>>>;

/// Removes an in-flight entry when the execution finishes, however it ends.
struct InFlightGuard {
    table: InFlight,
    key: (PeerId, [u8; 16]),
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.table.lock().remove(&self.key);
    }
}

/// The server half: executes tasks on the local kernel for authorized peers.
///
/// Clone is cheap; one instance serves every inbound connection, and clones
/// share the in-flight table.
#[derive(Clone)]
pub struct RemoteTaskServer {
    kernel: Arc<Kernel>,
    allowlist: Arc<dyn PeerAllowlist>,
    local_peer_id: PeerId,
    max_timeout_ms: u64,
    max_input_bytes: u64,
    max_output_bytes: u64,
    in_flight: InFlight,
    /// Metrics sink; `None` until [`RemoteTaskServer::with_metrics`].
    metrics: Option<entangle_observability::Registry>,
}

impl std::fmt::Debug for RemoteTaskServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteTaskServer")
            .field("local_peer_id", &self.local_peer_id)
            .field("allowlist", &self.allowlist)
            .field("max_timeout_ms", &self.max_timeout_ms)
            .field("max_input_bytes", &self.max_input_bytes)
            .field("max_output_bytes", &self.max_output_bytes)
            .field("in_flight", &self.in_flight.lock().len())
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
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            metrics: None,
        }
    }

    /// Count every answered frame by outcome into `registry`
    /// (`entangle_remote_serve_total`; outcomes: `ok`, `ack`, or a
    /// [`RemoteErrorCode`] label).
    #[must_use]
    pub fn with_metrics(mut self, registry: entangle_observability::Registry) -> Self {
        self.metrics = Some(registry);
        self
    }

    /// The policy hash of `caller`'s task `task_id`, if it is executing here
    /// right now.
    pub fn in_flight_policy(&self, caller: &PeerId, task_id: &TaskId) -> Option<PolicyHash> {
        self.in_flight
            .lock()
            .get(&(*caller, *task_id.as_bytes()))
            .copied()
    }

    /// Number of tasks executing here right now, across all callers.
    pub fn in_flight_len(&self) -> usize {
        self.in_flight.lock().len()
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
        if let Some(reg) = &self.metrics {
            let outcome = match &response.outcome {
                RemoteOutcome::Ok { .. } => "ok",
                RemoteOutcome::Ack { .. } => "ack",
                RemoteOutcome::Err { code, .. } => code.as_str(),
            };
            entangle_observability::catalog::remote_serve(reg, outcome);
        }
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
                    WireError::Malformed(_)
                    | WireError::OutputTooLarge { .. }
                    | WireError::PolicyTooLarge { .. } => RemoteErrorCode::MalformedRequest,
                };
                tracing::debug!(peer = %from, error = %e, "scheduler: rejected request envelope");
                return RemoteTaskResponse::err(code, e.to_string());
            }
        };

        match request.frame {
            RequestFrame::Task(task) => self.run_task(from, task).await,
            RequestFrame::Control(control) => self.control(from, control),
        }
    }

    /// Execute one task frame — exactly once — for `from`, inside a span that
    /// continues the submitter's trace when the frame carried a valid
    /// `traceparent`. The `traceparent` only picks the trace; it grants
    /// nothing (the allowlist check already ran, on the transport-authenticated
    /// identity).
    async fn run_task(&self, from: PeerId, request: RemoteTaskRequest) -> RemoteTaskResponse {
        let span = tracing::info_span!(
            "remote.task.execute",
            otel.kind = "server",
            peer = %from,
            plugin = %request.plugin,
        );
        if let Some(tp) = request.traceparent.as_deref() {
            entangle_observability::context::set_remote_parent(&span, tp);
        }
        self.run_task_inner(from, request).instrument(span).await
    }

    async fn run_task_inner(&self, from: PeerId, request: RemoteTaskRequest) -> RemoteTaskResponse {
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

        // INV-INT-1: verify the policy envelope before any work happens.
        let envelope = match PolicyEnvelope::open(request.policy, request.policy_hash) {
            Ok(env) => env,
            Err(e) => {
                tracing::warn!(peer = %from, error = %e, "scheduler: refused task with a bad policy envelope");
                return RemoteTaskResponse::err(RemoteErrorCode::PolicyHashMismatch, e.to_string());
            }
        };

        // §7.5 Rule 2, the part a worker can check: a metric reference must
        // carry the key its plugin id names. (Whether that key is trusted is
        // the submitter's call; the worker never runs the metric.)
        if let IntegrityPolicy::SemanticEquivalent { metric, .. } = envelope.policy() {
            if !metric.is_self_consistent() {
                return RemoteTaskResponse::err(
                    RemoteErrorCode::MalformedRequest,
                    format!(
                        "metric reference {} carries a publisher key that does not match \
                         its plugin id",
                        metric.plugin
                    ),
                );
            }
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

        // Register as in flight. One frame, one execution: a second frame
        // with the same id while this one runs is refused, not run twice.
        let key = (from, request.task_id);
        {
            let mut table = self.in_flight.lock();
            if table.contains_key(&key) {
                return RemoteTaskResponse::err(
                    RemoteErrorCode::DuplicateTask,
                    "a task with this id from this peer is already executing here",
                );
            }
            table.insert(key, envelope.hash());
        }
        let _in_flight = InFlightGuard {
            table: Arc::clone(&self.in_flight),
            key,
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
            // would let one frame request N executions. The policy travelled
            // only to be verified (INV-INT-1) and audited.
            integrity: IntegrityPolicy::None,
            timeout_ms,
        };

        // Audit: which policy (and, for SemanticEquivalent, which metric) the
        // caller says it will verify this replica with. The metric is never
        // loaded here (§7.5 Rule 3).
        let metric = match envelope.policy() {
            IntegrityPolicy::SemanticEquivalent { metric, .. } => Some(metric.to_string()),
            _ => None,
        };
        tracing::info!(
            peer = %from,
            plugin = %task.plugin,
            input_bytes = input_len,
            timeout_ms,
            policy = %envelope.policy().kind(),
            policy_hash = %envelope.hash(),
            metric = metric.as_deref().unwrap_or("-"),
            "scheduler: executing task for remote peer"
        );

        let result = self
            .kernel
            .invoke_with_integrity(&task, self.local_peer_id)
            .await;

        // INV-INT-1, second check: re-hash the bytes we hold and compare
        // with what we registered before echoing it back.
        let observed = envelope.recompute_hash();
        let registered = self.in_flight.lock().get(&key).copied();
        if registered != Some(observed) || observed != envelope.hash() {
            tracing::error!(peer = %from, "scheduler: policy envelope changed during execution");
            return RemoteTaskResponse::err(
                RemoteErrorCode::Internal,
                "policy envelope changed during execution",
            );
        }

        match result {
            Ok(output) => {
                let actual = output.len() as u64;
                if actual > output_cap {
                    return RemoteTaskResponse::err(
                        RemoteErrorCode::OutputTooLarge,
                        format!("output of {actual} bytes exceeds the {output_cap} byte limit"),
                    );
                }
                RemoteTaskResponse::ok(output, observed)
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

    /// Answer a control frame from `from`. Never executes anything.
    fn control(&self, from: PeerId, frame: ControlFrame) -> RemoteTaskResponse {
        let ControlAction::SetPolicy {
            policy,
            policy_hash,
        } = frame.action;
        if hash_canonical(&policy) != policy_hash {
            return RemoteTaskResponse::err(
                RemoteErrorCode::MalformedRequest,
                "control frame's policy_hash is not SHA-256 of its policy bytes",
            );
        }
        let current = self.in_flight.lock().get(&(from, frame.task_id)).copied();
        match current {
            None => RemoteTaskResponse::err(
                RemoteErrorCode::UnknownTask,
                "no task with this id from this peer is executing here",
            ),
            Some(h) if h == policy_hash => RemoteTaskResponse::ack(frame.task_id, h),
            Some(h) => {
                tracing::warn!(
                    peer = %from,
                    task = %TaskId::from_bytes(frame.task_id),
                    in_flight_policy = %h,
                    proposed_policy = %policy_hash,
                    "scheduler: refused a mid-flight integrity-policy mutation (INV-INT-1)"
                );
                RemoteTaskResponse::err(
                    RemoteErrorCode::PolicyMutation,
                    format!(
                        "the integrity policy of an in-flight task is immutable \
                         (task runs under {h})"
                    ),
                )
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
    use entangle_mesh_iroh::{MeshConn, MeshTransport, MAX_FRAME_BYTES};
    use entangle_types::errors::EntangleError;

    fn peer(byte: u8) -> PeerId {
        PeerId::from_public_key_bytes(&[byte; 32])
    }

    type Answer = dyn Fn(&[u8]) -> Result<Vec<u8>, MeshIrohError> + Send + Sync;

    /// A transport whose every request gets `answer(request frame)`.
    struct Canned(Box<Answer>);

    impl std::fmt::Debug for Canned {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Canned")
        }
    }

    #[async_trait::async_trait]
    impl MeshTransport for Canned {
        fn local_peer_id(&self) -> PeerId {
            peer(0)
        }
        fn local_public_key(&self) -> [u8; 32] {
            [0; 32]
        }
        fn local_addrs(&self) -> Vec<std::net::SocketAddr> {
            Vec::new()
        }
        async fn connect(&self, _peer: &IrohPeer) -> Result<MeshConn, MeshIrohError> {
            Err(MeshIrohError::Stream(
                "canned transport does not dial".into(),
            ))
        }
        async fn request(
            &self,
            _peer: &IrohPeer,
            payload: &[u8],
        ) -> Result<Vec<u8>, MeshIrohError> {
            (self.0)(payload)
        }
        async fn accept(&self) -> Result<Option<MeshConn>, MeshIrohError> {
            Ok(None)
        }
        async fn shutdown(&self) {}
    }

    /// A client whose only peer answers with `answer`; returns that peer.
    fn canned_client(
        answer: impl Fn(&[u8]) -> Result<Vec<u8>, MeshIrohError> + Send + Sync + 'static,
    ) -> (RemoteDispatch, PeerId) {
        let target = IrohPeer::new([7u8; 32], "127.0.0.1:9".parse().expect("addr"));
        let directory = PeerDirectory::new();
        directory.insert(target.clone());
        let client = RemoteDispatch::new(Arc::new(Canned(Box::new(answer))), Arc::new(directory));
        (client, target.peer_id)
    }

    fn small_task() -> (OneShotTask, PolicyEnvelope) {
        let mut task = OneShotTask::with_defaults(
            "0123456789abcdef0123456789abcdef/demo@1.0.0"
                .parse()
                .expect("plugin id"),
            b"in".to_vec(),
        );
        task.max_output_bytes = 1024;
        let envelope = PolicyEnvelope::seal(&task.integrity).expect("seal");
        (task, envelope)
    }

    /// INV-INT-2 / ATC-INT-5: an answer whose frame header declares more
    /// than the transport cap is refused by the transport before its body is
    /// read — and is still an *oversized output* (E0300), so the acceptance
    /// pipeline warns and penalises, rather than an ordinary transport
    /// failure that would let the peer dodge both.
    #[tokio::test]
    async fn a_response_frame_over_the_transport_cap_is_an_oversized_output() {
        let declared = 20 * 1024 * 1024;
        let (client, target) = canned_client(move |_| {
            Err(MeshIrohError::FrameTooLarge {
                declared,
                max: MAX_FRAME_BYTES,
            })
        });
        let (task, env) = small_task();
        match client.dispatch_sealed(&task, target, &env).await {
            Err(DispatchError::OutputSizeExceeded(EntangleError::OutputSizeExceeded {
                declared: d,
                actual,
                peer: p,
            })) => {
                assert_eq!((d, actual), (1024, declared));
                assert_eq!(p, target.to_hex());
            }
            other => panic!("expected OutputSizeExceeded, got {other:?}"),
        }
    }

    /// An oversized `Ok` answer with one trailing byte appended is still an
    /// oversized output, not a malformed frame.
    #[tokio::test]
    async fn an_oversized_answer_with_a_trailing_byte_is_an_oversized_output() {
        let (client, target) = canned_client(|_| {
            let h = crate::work_unit::policy_hash(&IntegrityPolicy::None);
            let mut bytes =
                encode_response(&RemoteTaskResponse::ok(vec![b'A'; 2048], h)).expect("encode");
            bytes.push(0);
            Ok(bytes)
        });
        let (task, env) = small_task();
        match client.dispatch_sealed(&task, target, &env).await {
            Err(DispatchError::OutputSizeExceeded(EntangleError::OutputSizeExceeded {
                declared,
                actual,
                ..
            })) => assert_eq!((declared, actual), (1024, 2048)),
            other => panic!("expected OutputSizeExceeded, got {other:?}"),
        }
    }

    /// A frame-cap refusal of *our own request* (the request frame is over
    /// the cap the error reports) says nothing about the peer's output and
    /// stays a transport failure.
    #[tokio::test]
    async fn our_own_oversized_request_is_not_blamed_on_the_peer() {
        let (client, target) = canned_client(|payload| {
            Err(MeshIrohError::FrameTooLarge {
                declared: payload.len() as u64,
                max: 1,
            })
        });
        let (task, env) = small_task();
        let err = client
            .dispatch_sealed(&task, target, &env)
            .await
            .expect_err("the transport refused the request");
        assert!(
            matches!(err, DispatchError::RemoteTransport { .. }),
            "{err:?}"
        );
    }

    /// Sends on its channel when dropped.
    struct SignalOnDrop(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for SignalOnDrop {
        fn drop(&mut self) {
            if let Some(tx) = self.0.take() {
                let _ = tx.send(());
            }
        }
    }

    /// A transport whose requests never answer. It reports when a request
    /// starts and when that request's future is dropped (cancelled).
    struct Hanging {
        started: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        dropped: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    }

    impl std::fmt::Debug for Hanging {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Hanging")
        }
    }

    #[async_trait::async_trait]
    impl MeshTransport for Hanging {
        fn local_peer_id(&self) -> PeerId {
            peer(0)
        }
        fn local_public_key(&self) -> [u8; 32] {
            [0; 32]
        }
        fn local_addrs(&self) -> Vec<std::net::SocketAddr> {
            Vec::new()
        }
        async fn connect(&self, _peer: &IrohPeer) -> Result<MeshConn, MeshIrohError> {
            Err(MeshIrohError::Stream(
                "hanging transport does not dial".into(),
            ))
        }
        async fn request(
            &self,
            _peer: &IrohPeer,
            _payload: &[u8],
        ) -> Result<Vec<u8>, MeshIrohError> {
            let _cancelled = SignalOnDrop(self.dropped.lock().take());
            if let Some(tx) = self.started.lock().take() {
                let _ = tx.send(());
            }
            std::future::pending().await
        }
        async fn accept(&self) -> Result<Option<MeshConn>, MeshIrohError> {
            Ok(None)
        }
        async fn shutdown(&self) {}
    }

    /// Dropping a dispatch (the RPC caller went away, an outer timeout
    /// fired) cancels its transport request, as awaiting the request inline
    /// did; it must not leave the request running detached until the peer
    /// answers.
    #[tokio::test]
    async fn dropping_a_dispatch_cancels_its_transport_request() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        let transport = Hanging {
            started: Mutex::new(Some(started_tx)),
            dropped: Mutex::new(Some(dropped_tx)),
        };
        let target = IrohPeer::new([7u8; 32], "127.0.0.1:9".parse().expect("addr"));
        let directory = PeerDirectory::new();
        directory.insert(target.clone());
        let client = RemoteDispatch::new(Arc::new(transport), Arc::new(directory));
        let (task, env) = small_task();
        let mut dispatch =
            Box::pin(async move { client.dispatch_sealed(&task, target.peer_id, &env).await });
        tokio::select! {
            r = &mut dispatch => panic!("a hanging transport cannot answer: {r:?}"),
            r = started_rx => r.expect("the transport request started"),
        }
        drop(dispatch);
        tokio::time::timeout(Duration::from_secs(5), dropped_rx)
            .await
            .expect("dropping the dispatch must cancel its transport request")
            .expect("the request future signalled its drop");
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
