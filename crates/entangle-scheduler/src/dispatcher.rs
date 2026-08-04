//! Task dispatcher: place a task, then run it — here or on another machine.
//!
//! Local execution goes straight to the in-process [`Kernel`]. Remote
//! execution is delegated to [`RemoteDispatch`], which is **optional**: a
//! dispatcher without one behaves exactly as it did before cross-node
//! dispatch existed, governed by [`Dispatcher::strict_remote`].

use crate::{
    placement::{choose, PlacementChoice, PlacementError},
    remote::RemoteDispatch,
    wire::RemoteErrorCode,
    worker::WorkerPool,
};
use entangle_runtime::Kernel;
use entangle_types::{peer_id::PeerId, task::OneShotTask};
use std::sync::Arc;
use std::time::Duration;

/// Errors that can arise during task dispatch.
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    /// Placement failed to find a suitable worker.
    #[error("placement: {0}")]
    Placement(#[from] PlacementError),
    /// The local kernel returned an error during invocation.
    #[error("local kernel error: {0}")]
    Runtime(#[from] entangle_runtime::RuntimeError),
    /// The task's `input` payload exceeded its declared `max_input_bytes`.
    ///
    /// Rejected before placement or invocation so an oversized request never
    /// reaches the kernel — the ingress-side mirror of the `ENTANGLE-E0300`
    /// output-size guard.
    #[error(
        "ENTANGLE-E0401: input exceeds max_input_bytes \
         (declared {declared}, actual {actual})"
    )]
    InputSizeExceeded {
        /// The `max_input_bytes` limit declared in the task.
        declared: u64,
        /// The actual size of the supplied input, in bytes.
        actual: u64,
    },
    /// The produced output exceeded the task's declared `max_output_bytes`.
    ///
    /// Reuses the canonical `ENTANGLE-E0300`
    /// [`EntangleError::OutputSizeExceeded`](entangle_types::errors::EntangleError::OutputSizeExceeded)
    /// semantics.
    #[error("{0}")]
    OutputSizeExceeded(entangle_types::errors::EntangleError),
    /// Placement chose a remote peer but this dispatcher has no transport
    /// configured, and `strict_remote` forbids the silent local fallback.
    ///
    /// Carries the chosen peer + human-readable placement reason so callers
    /// can surface a useful message without re-running placement.
    #[error(
        "ENTANGLE-E0400: remote dispatch not available (no mesh transport configured); \
         placement chose peer {peer} ({reason})"
    )]
    RemoteNotImplemented {
        /// The peer placement chose but could not be reached.
        peer: PeerId,
        /// Human-readable placement reason (from `PlacementChoice::reason`).
        reason: String,
    },
    /// The task never reached the chosen peer, or its answer never came back
    /// intelligibly: unknown address, dial failure, deadline exceeded, or a
    /// malformed / wrong-version response frame.
    ///
    /// Distinct from [`DispatchError::RemoteRejected`] on purpose: this means
    /// *we could not talk to them*, which is a retry-elsewhere condition,
    /// whereas a rejection means the peer answered and declined.
    #[error("ENTANGLE-E0402: remote dispatch to peer {peer} failed: {reason}")]
    RemoteTransport {
        /// The peer that could not be reached or understood.
        peer: PeerId,
        /// Underlying transport or wire failure, rendered as text.
        reason: String,
    },
    /// The chosen peer answered, and declined to produce output.
    ///
    /// `code` is the peer's own machine-readable reason — notably
    /// [`RemoteErrorCode::NotAuthorized`] when this node is not in that
    /// peer's trusted allowlist. `message` is untrusted diagnostic text:
    /// display it, never parse it.
    #[error("ENTANGLE-E0403: peer {peer} rejected the task ({code}): {message}")]
    RemoteRejected {
        /// The peer that rejected the task.
        peer: PeerId,
        /// The peer's machine-readable reason.
        code: RemoteErrorCode,
        /// The peer's human-readable detail.
        message: String,
    },
}

/// Combines a placement decision with the task output bytes.
#[derive(Clone, Debug)]
pub struct DispatchResult {
    /// The placement decision that was made.
    pub chosen: PlacementChoice,
    /// Raw output bytes returned by the plugin.
    pub output: Vec<u8>,
}

/// Task dispatcher backed by the local [`Kernel`] and, optionally, a mesh
/// transport for tasks that placement sends to another machine.
#[derive(Clone)]
pub struct Dispatcher {
    workers: WorkerPool,
    kernel: Arc<Kernel>,
    /// Local peer id — if placement chooses this peer, run in-process.
    local_peer_id: PeerId,
    /// Cross-node dispatch client. `None` — the default — means this node has
    /// no mesh transport configured and behaves exactly as a local-only node.
    remote: Option<Arc<RemoteDispatch>>,
    /// TTL for considering a worker live.
    pub worker_ttl: Duration,
    /// When true, refuse to silently fall back to local execution when
    /// placement chooses a remote peer that cannot be reached; instead,
    /// return [`DispatchError::RemoteNotImplemented`].
    ///
    /// Only consulted when no transport is configured: with a transport, a
    /// remote placement really does go remote and its failures are reported
    /// as themselves rather than being masked by a local re-run.
    pub strict_remote: bool,
}

impl Dispatcher {
    /// Create a new local-only dispatcher.
    ///
    /// Attach [`Dispatcher::with_remote`] to let remote placements actually
    /// execute on the chosen peer.
    pub fn new(workers: WorkerPool, kernel: Arc<Kernel>, local_peer_id: PeerId) -> Self {
        Self {
            workers,
            kernel,
            local_peer_id,
            remote: None,
            worker_ttl: Duration::from_secs(60),
            strict_remote: false,
        }
    }

    /// Enable strict remote enforcement.
    ///
    /// In strict mode a remote placement that cannot be shipped anywhere
    /// (no transport configured) returns
    /// [`DispatchError::RemoteNotImplemented`] instead of silently re-running
    /// on the local kernel.
    pub fn with_strict_remote(mut self, strict: bool) -> Self {
        self.strict_remote = strict;
        self
    }

    /// Attach a cross-node dispatch client.
    ///
    /// With one attached, a placement that names a peer other than
    /// `local_peer_id` is shipped to that peer over the mesh and its output
    /// returned. Without one, nothing changes for this node.
    #[must_use]
    pub fn with_remote(mut self, remote: Arc<RemoteDispatch>) -> Self {
        self.remote = Some(remote);
        self
    }

    /// Whether this dispatcher can execute work on another machine.
    pub fn has_remote(&self) -> bool {
        self.remote.is_some()
    }

    /// Dispatch a [`OneShotTask`]: place → run → return output.
    ///
    /// When placement chooses this node, the task runs on the local kernel.
    /// When it chooses another peer:
    ///
    /// * with a transport configured, the task is shipped there and that
    ///   node's output is returned — failures surface as
    ///   [`DispatchError::RemoteTransport`] or
    ///   [`DispatchError::RemoteRejected`];
    /// * with no transport and `strict_remote` set, the call fails with
    ///   [`DispatchError::RemoteNotImplemented`];
    /// * with no transport and `strict_remote` clear, execution falls back to
    ///   the local kernel with a warning — the historical behaviour.
    pub async fn dispatch_one_shot(
        &self,
        task: OneShotTask,
    ) -> Result<DispatchResult, DispatchError> {
        // Reject an oversized input before doing any placement or execution
        // work — an oversized request must never reach the kernel.
        let input_len = task.input.len() as u64;
        if input_len > task.max_input_bytes {
            return Err(DispatchError::InputSizeExceeded {
                declared: task.max_input_bytes,
                actual: input_len,
            });
        }

        let live = self.workers.live(self.worker_ttl);

        let chosen = choose(&live, &task.resources).or_else(|e| {
            match e {
                // No live workers and no resources required → use local kernel directly.
                PlacementError::NoWorkers
                    if task.resources.cpu_cores == 0.0 && task.resources.memory_bytes == 0 =>
                {
                    Ok(PlacementChoice {
                        peer_id: self.local_peer_id,
                        score: 0.0,
                        reason: "no workers — falling back to local".into(),
                    })
                }
                _ => Err(e),
            }
        })?;

        if chosen.peer_id != self.local_peer_id {
            match &self.remote {
                // The real thing: ship the task to the machine placement
                // picked and return what *it* produced.
                Some(remote) => {
                    tracing::debug!(
                        peer = %chosen.peer_id,
                        plugin = %task.plugin,
                        "dispatching task to remote peer"
                    );
                    let output = remote.dispatch(&task, chosen.peer_id).await?;

                    // The peer is untrusted: re-check the size limit against
                    // the task we asked for, naming the peer that broke it.
                    let output_len = output.len() as u64;
                    if output_len > task.max_output_bytes {
                        return Err(DispatchError::OutputSizeExceeded(
                            entangle_types::errors::EntangleError::OutputSizeExceeded {
                                declared: task.max_output_bytes,
                                actual: output_len,
                                peer: chosen.peer_id.to_hex(),
                            },
                        ));
                    }
                    return Ok(DispatchResult { chosen, output });
                }
                None if self.strict_remote => {
                    return Err(DispatchError::RemoteNotImplemented {
                        peer: chosen.peer_id,
                        reason: chosen.reason.clone(),
                    });
                }
                None => {
                    tracing::warn!(
                        ?chosen,
                        "no mesh transport configured; falling back to local execution"
                    );
                }
            }
        }

        // Enforce the task's integrity policy (spec §7.5): Deterministic
        // replicas, TrustedExecutor allowlists, and the NotImplemented
        // policies are all honoured here instead of being silently dropped.
        let output = self
            .kernel
            .invoke_with_integrity(&task, self.local_peer_id)
            .await?;

        // Reject an oversized output (ENTANGLE-E0300) before returning it.
        let output_len = output.len() as u64;
        if output_len > task.max_output_bytes {
            return Err(DispatchError::OutputSizeExceeded(
                entangle_types::errors::EntangleError::OutputSizeExceeded {
                    declared: task.max_output_bytes,
                    actual: output_len,
                    peer: self.local_peer_id.to_hex(),
                },
            ));
        }

        Ok(DispatchResult { chosen, output })
    }
}
