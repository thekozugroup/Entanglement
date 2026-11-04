//! The executor service ([`StreamServer`], [`serve_streams`]) and the
//! submitter's entry point ([`open_stream`]).
//!
//! # The executor gate, in order
//!
//! 1. **Authorization, before decoding anything.** The peer is the one the
//!    transport authenticated (`StreamIo::remote_peer_id`); unless the
//!    [`PeerAllowlist`] admits it, the stream gets one `Error {
//!    NotAuthorized }` frame and is closed — the `Open` frame is never even
//!    read.
//! 2. **The `Open` frame** is read under a cap of the input ceiling plus
//!    envelope overhead (checked from the frame header, before allocation)
//!    and a deadline, then decoded (version, structure).
//! 3. **The capability token**, before anything else is looked at: the
//!    `Open` must carry an attenuation of the `mesh.peer` token this node
//!    issued to the peer, bound to this `Open`, fresh and unrevoked
//!    ([`CapabilityGate`], see [`crate::capability`]); otherwise one `Error
//!    { CapabilityRequired | CapabilityRejected }` frame, and the plugin is
//!    never looked up.
//! 4. **The envelope**: the policy hash
//!    (INV-INT-1), the integrity policy (streams take only `TrustedExecutor`
//!    — which must name this node — or `None`), the input size, and the
//!    plugin (loaded here, as a stream plugin).
//! 5. **Capacity.** At most [`StreamCeilings::max_concurrent_streams`] at
//!    once; one stream per `(peer, task id)`.
//! 6. **Clamping.** Every requested limit is lowered to this node's
//!    [`StreamCeilings`]; the `Accepted` frame tells the submitter what
//!    applies.
//!
//! One `Open` is exactly one plugin execution: the policy is verified and
//! logged, never applied as replication.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use entangle_host::stream_port;
use entangle_mesh_iroh::{IrohPeer, MeshIroh, ALPN_STREAM};
use entangle_runtime::Kernel;
use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;
use entangle_types::plugin_id::PluginId;
use entangle_types::task::{StreamingTask, TaskId};
use parking_lot::Mutex;
use tokio::sync::mpsc;

use super::driver::{drive_executor_halves, ExecutorReport, StreamHandle, StreamOptions};
use super::error::{Reason, Side, StreamError};
use super::executor::{ExecutorConfig, ExecutorMachine};
use super::frame::{decode_frame, encode_frame, Frame, OPEN_FRAME_OVERHEAD};
use super::signing::{request_digest, ChunkSigner};
use super::validate::{
    check_executor_allowed, check_stream_integrity, validate_submit, StreamCeilings,
};
use super::{StreamEvent, STREAM_TRACE_TARGET};
use crate::capability::{stream_binding, CapabilityGate, GatePath};
use crate::remote::PeerAllowlist;
use crate::transport::{FrameError, FrameSend, StreamIo};
use crate::work_unit::PolicyEnvelope;

/// How long an authorized peer has to send its `Open` frame.
pub const OPEN_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a refusal (`Error` frame plus finish) may take to write. A peer
/// that does not take it in this time — one that never reads — gets its
/// stream reset instead, so it cannot pin the handler (or, on the
/// unauthorized path, anything at all) by not reading.
pub const REFUSE_TIMEOUT: Duration = Duration::from_secs(2);

/// Streams running on this executor: `(authenticated submitter, task id)`.
type InFlight = Arc<Mutex<HashSet<(PeerId, [u8; 16])>>>;

/// Removes an in-flight entry when its stream ends, however it ends.
struct InFlightGuard {
    table: InFlight,
    key: (PeerId, [u8; 16]),
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.table.lock().remove(&self.key);
    }
}

/// Executes streaming tasks on the local kernel for authorized peers.
///
/// Clone is cheap; clones share the in-flight table.
#[derive(Clone)]
pub struct StreamServer {
    kernel: Arc<Kernel>,
    allowlist: Arc<dyn PeerAllowlist>,
    /// `None` when no gate rooted at `identity` could be built: every stream
    /// is then refused (fail closed).
    gate: Option<Arc<CapabilityGate>>,
    identity: IdentityKeyPair,
    local_peer_id: PeerId,
    ceilings: StreamCeilings,
    in_flight: InFlight,
    events: Option<mpsc::UnboundedSender<(PeerId, StreamEvent)>>,
}

impl std::fmt::Debug for StreamServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamServer")
            .field("local_peer_id", &self.local_peer_id)
            .field("allowlist", &self.allowlist)
            .field(
                "requires_tokens",
                &self.gate.as_ref().map(|g| g.requires_tokens()),
            )
            .field("ceilings", &self.ceilings)
            .field("in_flight", &self.in_flight.lock().len())
            .finish_non_exhaustive()
    }
}

impl StreamServer {
    /// Serve `kernel`'s stream plugins to the peers `allowlist` admits,
    /// signing chunks with `identity` — which must be this node's transport
    /// identity, or submitters cannot verify a single chunk.
    ///
    /// Every `Open` must also carry a capability token rooted at `identity`
    /// (a default [`CapabilityGate`] requiring tokens); share one gate with
    /// the task server through [`StreamServer::with_capability_gate`].
    pub fn new(
        kernel: Arc<Kernel>,
        allowlist: Arc<dyn PeerAllowlist>,
        identity: IdentityKeyPair,
    ) -> Self {
        let local_peer_id = PeerId::from_public_key_bytes(identity.public().as_bytes());
        let gate = match CapabilityGate::for_identity(&identity) {
            Ok(g) => Some(Arc::new(g)),
            Err(e) => {
                tracing::error!(target: STREAM_TRACE_TARGET, error = %e, "no capability gate for this identity; every stream will be refused");
                None
            }
        };
        Self {
            kernel,
            allowlist,
            gate,
            identity,
            local_peer_id,
            ceilings: StreamCeilings::default(),
            in_flight: Arc::new(Mutex::new(HashSet::new())),
            events: None,
        }
    }

    /// Verify capability tokens with `gate` (e.g. the one the task server
    /// uses, so both share a replay cache and revocation set). The gate must
    /// be rooted at this server's identity; one that is not makes every
    /// stream refused (fail closed) and is logged.
    #[must_use]
    pub fn with_capability_gate(mut self, gate: Arc<CapabilityGate>) -> Self {
        if gate.local_public_key() == self.identity.public().as_bytes() {
            self.gate = Some(gate);
        } else {
            tracing::error!(target: STREAM_TRACE_TARGET, "capability gate is rooted at another identity; every stream will be refused");
            self.gate = None;
        }
        self
    }

    /// Tighten the ceilings (they are clamped: see
    /// [`StreamCeilings::clamped`]).
    #[must_use]
    pub fn with_ceilings(mut self, ceilings: StreamCeilings) -> Self {
        self.ceilings = ceilings.clamped();
        self
    }

    /// Report every stream event, tagged with the submitter's peer id.
    #[must_use]
    pub fn with_events(mut self, events: mpsc::UnboundedSender<(PeerId, StreamEvent)>) -> Self {
        self.events = Some(events);
        self
    }

    /// The ceilings in force.
    pub const fn ceilings(&self) -> &StreamCeilings {
        &self.ceilings
    }

    /// This node's peer id (the chunk-signing identity).
    pub const fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// This node's raw public key (the chunk-signing key).
    pub fn local_public_key(&self) -> [u8; 32] {
        *self.identity.public().as_bytes()
    }

    /// Streams running right now, across all peers.
    pub fn in_flight_len(&self) -> usize {
        self.in_flight.lock().len()
    }

    /// Serve one inbound stream (over any transport) to its end. See the
    /// module docs for the gate. `Err` means the stream was refused before
    /// the plugin ran.
    pub async fn handle<I: Into<StreamIo>>(&self, io: I) -> Result<ExecutorReport, StreamError> {
        let io: StreamIo = io.into();
        let peer = io.remote_peer_id();
        let transport = io.transport();
        // An attached connection (none on the serving side) closes with `io`.
        let (mut send, mut recv, _conn) = io.into_parts();

        // ── THE SECURITY GATE ────────────────────────────────────────────
        // `peer` is the identity the transport authenticated. Check it
        // before reading a byte of the stream: an unauthorized peer gets
        // neither this node's frame decoder nor its kernel.
        if !self.allowlist.is_authorized(&peer) {
            tracing::warn!(
                target: STREAM_TRACE_TARGET,
                %peer,
                transport = transport.as_str(),
                "refused a stream from a peer that is not in the trusted allowlist"
            );
            let refusal = StreamError::PeerAborted {
                by: Side::Executor,
                reason: Reason::NotAuthorized,
                message: "peer is not in this node's trusted peer allowlist".into(),
            };
            refuse(&mut send, Reason::NotAuthorized, &refusal.to_string()).await;
            return Err(refusal);
        }

        let open_cap = usize::try_from(self.ceilings.max_input_bytes)
            .unwrap_or(usize::MAX)
            .saturating_add(OPEN_FRAME_OVERHEAD);
        let first = match tokio::time::timeout(OPEN_READ_TIMEOUT, recv.recv_capped(open_cap)).await
        {
            Ok(Ok(Some(bytes))) => bytes,
            Ok(Ok(None)) => return Err(StreamError::Transport("stream ended before Open".into())),
            Ok(Err(FrameError::TooLarge { declared, .. })) => {
                let err = StreamError::InputTooLarge {
                    declared: self.ceilings.max_input_bytes,
                    actual: declared.saturating_sub(OPEN_FRAME_OVERHEAD as u64),
                };
                refuse(&mut send, err.reason(), &err.to_string()).await;
                return Err(err);
            }
            Ok(Err(e)) => return Err(StreamError::Transport(e.to_string())),
            Err(_) => {
                let err = StreamError::Timeout {
                    after_ms: OPEN_READ_TIMEOUT.as_millis() as u64,
                };
                refuse(&mut send, err.reason(), "no Open frame in time").await;
                return Err(err);
            }
        };

        let decoded = decode_frame(&first, Side::Submitter);
        // The raw frame is no longer needed (the input lives on in `open`).
        drop(first);
        let open = match decoded {
            Ok(Frame::Open(open)) => open,
            Ok(other) => {
                let err = StreamError::Protocol {
                    by: Side::Submitter,
                    detail: format!("the first frame must be Open, got {}", other.name()),
                };
                refuse(&mut send, err.reason(), &err.to_string()).await;
                return Err(err);
            }
            Err(err) => {
                refuse(&mut send, err.reason(), &err.to_string()).await;
                return Err(err);
            }
        };

        // What every chunk signature will commit the output to.
        let request = request_digest(&open);

        // ── THE CAPABILITY GATE ──────────────────────────────────────────
        // Before the policy, the plugin or any slot is looked at: the token
        // must be this node's, issued to `peer`, bound to this `Open`, fresh
        // and unrevoked.
        let binding = stream_binding(&open.task_id, &open.policy_hash, &request);
        let admitted = match &self.gate {
            Some(gate) => gate
                .check(peer, open.capability.as_deref(), binding, GatePath::Stream)
                .map_err(|refusal| {
                    let reason = if refusal.is_missing() {
                        Reason::CapabilityRequired
                    } else {
                        Reason::CapabilityRejected
                    };
                    (reason, refusal.error.to_string())
                }),
            None => Err((
                Reason::CapabilityRejected,
                "this node has no capability verifier for its identity".to_owned(),
            )),
        };
        if let Err((reason, message)) = admitted {
            drop(open.input);
            tracing::warn!(target: STREAM_TRACE_TARGET, %peer, transport = transport.as_str(), %reason, "refused a stream: {message}");
            refuse(&mut send, reason, &message).await;
            return Err(StreamError::PeerAborted {
                by: Side::Executor,
                reason,
                message,
            });
        }

        // INV-INT-1: verify the policy envelope before any work happens.
        let envelope = match PolicyEnvelope::open(open.policy, open.policy_hash) {
            Ok(env) => env,
            Err(e) => {
                let err = StreamError::Policy(e.to_string());
                refuse(&mut send, Reason::PolicyHashMismatch, &err.to_string()).await;
                return Err(err);
            }
        };
        let checks = check_stream_integrity(envelope.policy())
            .and_then(|()| check_executor_allowed(envelope.policy(), &self.local_peer_id))
            .and_then(|()| {
                let actual = open.input.len() as u64;
                let declared = open.max_input_bytes.min(self.ceilings.max_input_bytes);
                if actual > declared {
                    Err(StreamError::InputTooLarge { declared, actual })
                } else {
                    Ok(())
                }
            })
            .and_then(|()| self.ceilings.accept(&open.channel, open.timeout_ms));
        let limits = match checks {
            Ok(limits) => limits,
            Err(err) => {
                refuse(&mut send, err.reason(), &err.to_string()).await;
                return Err(err);
            }
        };
        let plugin: PluginId = match open.plugin.parse() {
            Ok(id) => id,
            Err(e) => {
                let err = StreamError::InvalidTask {
                    field: "plugin",
                    reason: format!("{:?}: {e}", open.plugin),
                };
                refuse(&mut send, err.reason(), &err.to_string()).await;
                return Err(err);
            }
        };
        if self.kernel.plugin_world(&plugin) != Some("stream-plugin") {
            let message = match self.kernel.plugin_world(&plugin) {
                Some(world) => {
                    format!("plugin {plugin} is a `{world}` plugin, not a stream plugin")
                }
                None => format!("plugin {plugin} is not loaded on this node"),
            };
            refuse(&mut send, Reason::PluginNotLoaded, &message).await;
            return Err(StreamError::PeerAborted {
                by: Side::Executor,
                reason: Reason::PluginNotLoaded,
                message,
            });
        }

        let key = (peer, open.task_id);
        let busy = {
            let mut table = self.in_flight.lock();
            if table.contains(&key) {
                Some("a stream with this task id from this peer is already running here")
            } else if table.len() >= self.ceilings.max_concurrent_streams {
                Some("this node is running its maximum number of streams")
            } else {
                table.insert(key);
                None
            }
        };
        if let Some(message) = busy {
            // Not running it: do not keep its input while refusing it.
            drop(open.input);
            refuse(&mut send, Reason::Busy, message).await;
            return Err(StreamError::PeerAborted {
                by: Side::Executor,
                reason: Reason::Busy,
                message: message.to_owned(),
            });
        }
        // The slot is held by this call *and* by the plugin's task, so it is
        // freed only once the stream has closed and the guest is gone (an
        // aborted guest stops at its next host call or its epoch deadline).
        let in_flight = Arc::new(InFlightGuard {
            table: Arc::clone(&self.in_flight),
            key,
        });

        let task_id = TaskId::from_bytes(open.task_id);
        tracing::info!(
            target: STREAM_TRACE_TARGET,
            %peer,
            %plugin,
            transport = transport.as_str(),
            task = %task_id,
            input_bytes = open.input.len(),
            policy = %envelope.policy().kind(),
            policy_hash = %envelope.hash(),
            credit_window = limits.credit_window,
            max_total_bytes = limits.max_total_bytes,
            timeout_ms = limits.timeout.as_millis() as u64,
            "streaming task for remote peer"
        );

        let machine = ExecutorMachine::new(
            ExecutorConfig {
                task_id,
                policy_hash: envelope.hash(),
                request,
                limits,
                local_peer: self.local_peer_id,
            },
            ChunkSigner::new(
                self.identity.clone(),
                open.task_id,
                envelope.hash(),
                request,
            ),
            Instant::now(),
        );
        let (port, driver_port) = stream_port(1);
        let kernel = Arc::clone(&self.kernel);
        let input = open.input;
        let timeout_ms = u64::try_from(limits.timeout.as_millis()).unwrap_or(u64::MAX);
        let slot = Arc::clone(&in_flight);
        let plugin_run = async move {
            let _slot = slot;
            kernel
                .invoke_stream(&plugin, &input, port, timeout_ms)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        };
        let events = self.events.clone().map(|tx| {
            let (etx, mut erx) = mpsc::unbounded_channel::<StreamEvent>();
            tokio::spawn(async move {
                while let Some(event) = erx.recv().await {
                    if tx.send((peer, event)).is_err() {
                        return;
                    }
                }
            });
            etx
        });
        let report =
            drive_executor_halves(machine, send, recv, driver_port, plugin_run, events).await;
        drop(in_flight);
        Ok(report)
    }
}

/// Send one `Error` frame and finish the stream, giving up after
/// [`REFUSE_TIMEOUT`] (the caller then drops the stream unfinished, which
/// resets it).
async fn refuse(send: &mut Box<dyn FrameSend>, reason: Reason, message: &str) {
    let write = async {
        if let Ok(bytes) = encode_frame(&Frame::error(reason, message)) {
            let _ = send.send(&bytes).await;
        }
        let _ = send.finish().await;
    };
    if tokio::time::timeout(REFUSE_TIMEOUT, write).await.is_err() {
        tracing::debug!(
            target: STREAM_TRACE_TARGET,
            %reason,
            "peer did not take the refusal in time; resetting the stream"
        );
    }
}

/// Serve `entangle/stream/1` on `transport` until it is shut down.
///
/// `transport` must accept [`ALPN_STREAM`] (as its primary ALPN or in
/// `extra_alpns`), and its identity must be `server`'s signing identity.
pub async fn serve_streams(transport: Arc<MeshIroh>, server: Arc<StreamServer>) {
    use entangle_mesh_iroh::MeshTransport as _;
    if transport.local_public_key() != server.local_public_key() {
        tracing::error!(
            target: STREAM_TRACE_TARGET,
            "refusing to serve streams: the transport identity is not the chunk-signing \
             identity, so no submitter could verify a chunk"
        );
        return;
    }
    loop {
        let conn = match transport.accept_alpn(ALPN_STREAM).await {
            Ok(Some(conn)) => conn,
            Ok(None) => return,
            Err(entangle_mesh_iroh::MeshIrohError::Protocol(e)) => {
                tracing::error!(target: STREAM_TRACE_TARGET, error = %e, "cannot serve streams");
                return;
            }
            Err(e) => {
                tracing::warn!(target: STREAM_TRACE_TARGET, error = %e, "rejected inbound stream connection");
                continue;
            }
        };
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            loop {
                match conn.accept_stream().await {
                    Ok(Some(io)) => {
                        let server = Arc::clone(&server);
                        tokio::spawn(async move {
                            if let Err(e) = server.handle(io).await {
                                tracing::debug!(target: STREAM_TRACE_TARGET, error = %e, "stream refused");
                            }
                        });
                    }
                    Ok(None) => return,
                    Err(e) => {
                        tracing::debug!(target: STREAM_TRACE_TARGET, error = %e, "stream connection ended");
                        return;
                    }
                }
            }
        });
    }
}

/// Submit `task` as a stream to `peer` over one iroh endpoint: validate it
/// (ATC-INT-4), check that its policy trusts `peer`, dial `peer` under
/// [`ALPN_STREAM`] and start streaming.
///
/// Chunks verify against the key the QUIC handshake authenticated for
/// `peer`. Nothing is dialled when validation fails. To choose among
/// several transports per peer, use
/// [`TransportRouter::open_stream`](crate::transport::TransportRouter::open_stream).
pub async fn open_stream(
    transport: &MeshIroh,
    peer: &IrohPeer,
    task: &StreamingTask,
    options: StreamOptions,
) -> Result<StreamHandle, StreamError> {
    validate_submit(task)?;
    check_executor_allowed(&task.integrity, &peer.peer_id)?;
    let conn = transport
        .connect_alpn(peer, ALPN_STREAM)
        .await
        .map_err(|e| StreamError::Transport(e.to_string()))?;
    let io = match conn.open_stream().await {
        Ok(io) => io,
        Err(e) => {
            conn.close();
            return Err(StreamError::Transport(e.to_string()));
        }
    };
    StreamHandle::start(StreamIo::from(io).with_connection(conn), task, options)
}
