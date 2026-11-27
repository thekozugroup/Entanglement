//! Task dispatcher: place a task, then run it — here or on another machine.
//!
//! Local execution goes straight to the in-process [`Kernel`]. Remote
//! execution is delegated to [`RemoteDispatch`], which is **optional**: a
//! dispatcher without one behaves exactly as it did before cross-node
//! dispatch existed, governed by [`Dispatcher::strict_remote`].

use crate::{
    placement::{PlacementChoice, PlacementError},
    remote::RemoteDispatch,
    wire::RemoteErrorCode,
    worker::{InFlight, WorkerInfo, WorkerPool},
};
use entangle_runtime::Kernel;
use entangle_types::{
    peer_id::PeerId,
    resource::ResourceSpec,
    task::{IntegrityPolicy, OneShotTask},
};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

/// Errors that can arise during task dispatch.
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    /// Submitter rejected the integrity policy, signed result or replica quorum.
    #[error("integrity: {0}")]
    Integrity(String),
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

/// Refresh cached worker inventory before an otherwise unplaceable task starts.
#[async_trait::async_trait]
pub trait PlacementRefresh: Send + Sync {
    /// Return true if an eligible peer supplied a fresh authenticated report.
    async fn refresh(&self, task: &OneShotTask) -> bool;
}

/// Task dispatcher backed by the local [`Kernel`] and, optionally, a mesh
/// transport for tasks that placement sends to another machine.
#[derive(Clone)]
pub struct Dispatcher {
    pub(crate) workers: WorkerPool,
    pub(crate) kernel: Arc<Kernel>,
    /// Local peer id — if placement chooses this peer, run in-process.
    pub(crate) local_peer_id: PeerId,
    /// Locally measured hardware, independent of network observation lifetimes.
    local_worker: Option<WorkerInfo>,
    local_in_flight: InFlight,
    /// Cross-node dispatch client. `None` — the default — means this node has
    /// no mesh transport configured and behaves exactly as a local-only node.
    pub(crate) remote: Option<Arc<RemoteDispatch>>,
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
            local_worker: None,
            local_in_flight: InFlight::default(),
            remote: None,
            worker_ttl: Duration::from_secs(60),
            strict_remote: false,
        }
    }

    /// Include this node's hardware in placement when its kernel has the requested plugin.
    /// Local hardware does not expire with network advertisements. A descriptor with
    /// invalid hardware values or a different peer identity is discarded.
    #[must_use]
    pub fn with_local_worker(mut self, worker: WorkerInfo) -> Self {
        if worker.peer_id == self.local_peer_id && worker.validate().is_ok() {
            self.local_worker = Some(worker);
        } else {
            tracing::warn!(peer = %worker.peer_id, "discarding invalid local worker descriptor");
        }
        self
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

    /// Select a live remote worker advertising this plugin, then open a signed
    /// stream. Policy validation happens before address lookup or network I/O.
    pub async fn dispatch_stream(
        &self,
        task: entangle_types::task::StreamingTask,
        input: &[u8],
    ) -> Result<(PeerId, crate::stream::StreamingClient), crate::stream::StreamError> {
        crate::stream::validate(&task, input.len(), None)?;
        let remote = self.remote.as_ref().ok_or_else(|| {
            crate::stream::StreamError::Invalid("no remote scheduler transport".into())
        })?;
        let (choice, reservation) = self
            .workers
            .choose_stream(self.worker_ttl, &task.resources, &task.plugin, |peer| {
                *peer != self.local_peer_id
                    && match &task.integrity {
                        IntegrityPolicy::TrustedExecutor { allowlist } => allowlist.contains(peer),
                        _ => true,
                    }
            })
            .map_err(|e| crate::stream::StreamError::Invalid(e.to_string()))?;
        let mut stream = remote.open_stream(choice.peer_id, task, input).await?;
        stream.reservation = Some(reservation);
        Ok((choice.peer_id, stream))
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
    ///   the local kernel if the task has no resource requirements or a
    ///   live local advertisement satisfies them.
    pub async fn dispatch_one_shot(
        &self,
        task: OneShotTask,
    ) -> Result<DispatchResult, DispatchError> {
        self.dispatch_one_shot_with_refresh(task, None).await
    }

    /// After a pre-execution miss, optionally refresh placement information and
    /// select once more. An attempted invocation is never repeated.
    pub async fn dispatch_one_shot_with_refresh(
        &self,
        mut task: OneShotTask,
        refresh: Option<&dyn PlacementRefresh>,
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

        if let IntegrityPolicy::SemanticEquivalent { metric, threshold } = &task.integrity {
            return tokio::time::timeout(
                Duration::from_millis(task.timeout_ms),
                self.semantic(&task, metric, *threshold),
            )
            .await
            .map_err(|_| DispatchError::Integrity("semantic task deadline exceeded".into()))?;
        }

        let trusted: Option<HashSet<_>> = match &task.integrity {
            IntegrityPolicy::TrustedExecutor { allowlist } => Some(allowlist.iter().collect()),
            _ => None,
        };
        let unconstrained = matches!(
            task.resources,
            ResourceSpec {
                cpu_cores: 0.0,
                memory_bytes: 0,
                gpu: None,
                npu: None,
                network_bandwidth_bps: 0,
            }
        );
        let local = self
            .local_worker
            .as_ref()
            .filter(|_| self.kernel.has_compute_plugin(&task.plugin))
            .map(|worker| (worker, &self.local_in_flight));
        let local_allowed = self.local_worker.is_none() || local.is_some();
        let place = || {
            self.workers.choose(
                self.worker_ttl,
                &task.resources,
                &task.plugin,
                task.input.len(),
                local,
                |peer| {
                    (*peer != self.local_peer_id || local_allowed)
                        && trusted.as_ref().is_none_or(|peers| peers.contains(peer))
                },
            )
        };
        let (mut chosen, mut _reservation) = match place() {
            Ok(chosen) => chosen,
            Err(PlacementError::NoWorkers)
                if unconstrained
                    && local_allowed
                    && trusted
                        .as_ref()
                        .is_none_or(|peers| peers.contains(&self.local_peer_id)) =>
            {
                (
                    PlacementChoice {
                        peer_id: self.local_peer_id,
                        score: 0.0,
                        reason: "no eligible workers — falling back to local".into(),
                    },
                    self.local_in_flight.reserve(),
                )
            }
            Err(initial) => {
                let Some(refresh) = refresh.filter(|_| {
                    self.remote.is_some()
                        && matches!(
                            task.integrity,
                            IntegrityPolicy::None | IntegrityPolicy::TrustedExecutor { .. }
                        )
                        && task.timeout_ms > 0
                }) else {
                    return Err(initial.into());
                };
                let start = tokio::time::Instant::now();
                let budget = Duration::from_millis(task.timeout_ms);
                let refreshed = tokio::time::timeout(budget, refresh.refresh(&task)).await;
                if !matches!(refreshed, Ok(true)) {
                    return Err(initial.into());
                }
                let remaining_ms = budget.saturating_sub(start.elapsed()).as_millis() as u64;
                if remaining_ms == 0 {
                    return Err(initial.into());
                }
                let chosen = place()?;
                task.timeout_ms = remaining_ms;
                chosen
            }
        };

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
                    let (output, upload) = remote.dispatch_measured(&task, chosen.peer_id).await?;

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
                    if let Some(bps) = upload {
                        self.workers
                            .record_upload(&chosen.peer_id, &_reservation, bps);
                    }
                    return Ok(DispatchResult { chosen, output });
                }
                None if self.strict_remote => {
                    return Err(DispatchError::RemoteNotImplemented {
                        peer: chosen.peer_id,
                        reason: chosen.reason,
                    });
                }
                None => {
                    tracing::warn!(
                        ?chosen,
                        "no mesh transport configured; checking local fallback"
                    );
                    (chosen, _reservation) = if unconstrained && local_allowed {
                        (
                            PlacementChoice {
                                peer_id: self.local_peer_id,
                                score: 0.0,
                                reason: "no mesh transport — falling back to local".into(),
                            },
                            self.local_in_flight.reserve(),
                        )
                    } else {
                        // A remote advert says nothing about the local hardware.
                        self.workers.choose(
                            self.worker_ttl,
                            &task.resources,
                            &task.plugin,
                            task.input.len(),
                            local,
                            |peer| *peer == self.local_peer_id && local_allowed,
                        )?
                    };
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
