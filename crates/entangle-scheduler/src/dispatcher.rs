//! Task dispatcher: place a task, then run it — here or on another machine.
//!
//! Local execution goes straight to the in-process [`Kernel`]. Remote
//! execution is delegated to [`RemoteDispatch`], which is **optional**: a
//! dispatcher without one behaves exactly as it did before cross-node
//! dispatch existed, governed by [`Dispatcher::strict_remote`].
//!
//! # Integrity (spec §7.5)
//!
//! Every dispatch goes through the submitter-side [`IntegrityVerifier`]:
//! the policy is validated and sealed before placement (so a refused policy
//! — e.g. a metric not on this node's keyring — dispatches nothing), and
//! every result passes the acceptance pipeline in [`crate::integrity`].
//!
//! Replicated policies — `Deterministic { replicas: N >= 2 }` and
//! `SemanticEquivalent` — put their replicas on **distinct** placement
//! targets: the best-ranked live remote workers that satisfy the task's
//! resources and whose reputation for this policy variant is not
//! `Excluded`, at most one replica per worker. Replicas left over when there
//! are fewer eligible remote workers than `N` (or no transport) run on the
//! local kernel. All replicas run concurrently.

use crate::{
    integrity::{replica_count, IntegrityVerifier, ReplicaBytes, ReplicaReport, ReplicaResult},
    placement::{choose, rank, PlacementChoice, PlacementError},
    remote::RemoteDispatch,
    wire::RemoteErrorCode,
    work_unit::{PolicyEnvelope, PolicyHash},
    worker::{WorkerInfo, WorkerPool},
};
use entangle_runtime::{IntegrityError, Kernel};
use entangle_types::{
    peer_id::PeerId,
    task::{IntegrityPolicy, OneShotTask},
};
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
    /// The task's integrity policy was refused at submit time, or its
    /// replicas failed verification (`ENTANGLE-E0302`–`E0349`; see
    /// [`IntegrityError`]). An oversized replica is reported as
    /// [`DispatchError::OutputSizeExceeded`] instead.
    #[error("{0}")]
    Integrity(#[from] IntegrityError),
}

/// Combines a placement decision with the task output bytes.
#[derive(Clone, Debug)]
pub struct DispatchResult {
    /// The placement decision for the replica whose output was returned.
    pub chosen: PlacementChoice,
    /// Raw output bytes returned by the plugin.
    pub output: Vec<u8>,
    /// The task's policy hash `H` (INV-INT-1).
    pub policy_hash: PolicyHash,
    /// One audit record per replica, in dispatch order.
    pub replicas: Vec<ReplicaReport>,
    /// For `SemanticEquivalent`: `(agreeing pairs, pairs compared)`.
    pub pair_agreement: Option<(usize, usize)>,
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
    /// Submitter-side integrity state: metric registry + reputation.
    verifier: Arc<IntegrityVerifier>,
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
    ///
    /// The integrity verifier trusts metrics signed by keys on the kernel's
    /// keyring; replace it with [`Dispatcher::with_verifier`].
    pub fn new(workers: WorkerPool, kernel: Arc<Kernel>, local_peer_id: PeerId) -> Self {
        let verifier = Arc::new(IntegrityVerifier::new(kernel.keyring(), local_peer_id));
        Self {
            workers,
            kernel,
            local_peer_id,
            remote: None,
            verifier,
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

    /// Replace the integrity verifier (e.g. to share one across dispatchers).
    #[must_use]
    pub fn with_verifier(mut self, verifier: Arc<IntegrityVerifier>) -> Self {
        self.verifier = verifier;
        self
    }

    /// The submitter-side integrity verifier: load metric components through
    /// `verifier().metrics()`, inspect reputation through
    /// `verifier().reputation()`.
    pub fn verifier(&self) -> &Arc<IntegrityVerifier> {
        &self.verifier
    }

    /// This node's peer id.
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Whether this dispatcher can execute work on another machine.
    pub fn has_remote(&self) -> bool {
        self.remote.is_some()
    }

    /// Dispatch a [`OneShotTask`]: validate → place → run → verify → return.
    ///
    /// The task's integrity policy is validated and sealed first; a refused
    /// policy dispatches nothing. Then, for a single-replica policy (`None`,
    /// `TrustedExecutor`, `Deterministic { 0 | 1 }`):
    ///
    /// When placement chooses this node, the task runs on the local kernel.
    /// When it chooses another peer:
    ///
    /// * with a transport configured, the task is shipped there and that
    ///   node's output returned — failures surface as
    ///   [`DispatchError::RemoteTransport`] or
    ///   [`DispatchError::RemoteRejected`];
    /// * with no transport and `strict_remote` set, the call fails with
    ///   [`DispatchError::RemoteNotImplemented`];
    /// * with no transport and `strict_remote` clear, execution falls back to
    ///   the local kernel with a warning — the historical behaviour.
    ///
    /// `TrustedExecutor` only places onto allow-listed peers.
    ///
    /// Replicated policies fan out as described in the module docs. Either
    /// way the result passes the acceptance pipeline of
    /// [`IntegrityVerifier::accept`].
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

        // Submit-time validation (ATC-INT-2 lives here): nothing has been
        // placed or sent yet.
        let envelope = self.verifier.validate_submit(&task.integrity)?;

        let replicated = matches!(
            task.integrity,
            IntegrityPolicy::SemanticEquivalent { .. }
                | IntegrityPolicy::Deterministic { replicas: 2.. }
        );
        if replicated {
            self.dispatch_replicated(task, envelope).await
        } else {
            self.dispatch_single(task, envelope).await
        }
    }

    /// The single-replica path (see [`Dispatcher::dispatch_one_shot`]).
    async fn dispatch_single(
        &self,
        task: OneShotTask,
        envelope: PolicyEnvelope,
    ) -> Result<DispatchResult, DispatchError> {
        let mut live = self.workers.live(self.worker_ttl);
        if let IntegrityPolicy::TrustedExecutor { allowlist } = &task.integrity {
            // Only an allow-listed executor may be chosen. If none is in the
            // pool, the local fallback below still applies the kernel's own
            // allowlist check to this node.
            live.retain(|w| allowlist.contains(&w.peer_id));
        }

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

        let mut run_local = chosen.peer_id == self.local_peer_id;
        if !run_local {
            match &self.remote {
                Some(_) => {}
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
                    run_local = true;
                }
            }
        }

        let replica = if run_local {
            // Enforce the task's policy on the local kernel (TrustedExecutor
            // allowlist, Deterministic { 0 | 1 } as a single invocation).
            let outcome = self
                .kernel
                .invoke_with_integrity(&task, self.local_peer_id)
                .await
                .map(|bytes| ReplicaBytes {
                    bytes,
                    observed_policy_hash: envelope.recompute_hash(),
                })
                .map_err(DispatchError::from);
            ReplicaResult {
                peer: self.local_peer_id,
                remote: false,
                outcome,
            }
        } else {
            tracing::debug!(
                peer = %chosen.peer_id,
                plugin = %task.plugin,
                "dispatching task to remote peer"
            );
            self.remote_replica(&task, chosen.peer_id, &envelope).await
        };

        let acceptance = self
            .verifier
            .accept(&task, &envelope, vec![replica])
            .await?;
        Ok(DispatchResult {
            chosen,
            output: acceptance.output,
            policy_hash: envelope.hash(),
            replicas: acceptance.reports,
            pair_agreement: acceptance.pair_agreement,
        })
    }

    /// The replicated path (see the module docs).
    async fn dispatch_replicated(
        &self,
        task: OneShotTask,
        envelope: PolicyEnvelope,
    ) -> Result<DispatchResult, DispatchError> {
        let n = replica_count(&task.integrity);
        let kind = task.integrity.kind();

        let live: Vec<WorkerInfo> = self.workers.live(self.worker_ttl);
        let ranked = match rank(&live, &task.resources) {
            Ok(r) => r,
            Err(PlacementError::NoWorkers)
                if task.resources.cpu_cores == 0.0 && task.resources.memory_bytes == 0 =>
            {
                Vec::new()
            }
            Err(e) => return Err(e.into()),
        };

        // Distinct remote targets, best first, skipping peers whose
        // reputation for this policy variant is Excluded.
        let mut targets: Vec<PlacementChoice> = Vec::new();
        match &self.remote {
            Some(_) => {
                for choice in ranked {
                    if targets.len() == n {
                        break;
                    }
                    if choice.peer_id == self.local_peer_id {
                        continue;
                    }
                    if !self
                        .verifier
                        .reputation()
                        .is_eligible(&choice.peer_id, kind)
                    {
                        tracing::info!(
                            peer = %choice.peer_id,
                            policy = %kind,
                            "skipping replica target with excluded reputation"
                        );
                        continue;
                    }
                    targets.push(choice);
                }
            }
            None => {
                if let Some(best) = ranked.first() {
                    if best.peer_id != self.local_peer_id && self.strict_remote {
                        return Err(DispatchError::RemoteNotImplemented {
                            peer: best.peer_id,
                            reason: best.reason.clone(),
                        });
                    }
                }
            }
        }
        let remote_count = targets.len();
        for k in remote_count..n {
            targets.push(PlacementChoice {
                peer_id: self.local_peer_id,
                score: 0.0,
                reason: format!(
                    "replica {} of {n} on the local kernel ({remote_count} distinct remote \
                     worker(s) available)",
                    k + 1
                ),
            });
        }
        tracing::debug!(
            plugin = %task.plugin,
            policy = %kind,
            replicas = n,
            remote = remote_count,
            policy_hash = %envelope.hash(),
            "dispatching replicated task"
        );

        // Run every replica concurrently; keep results in dispatch order.
        let task = Arc::new(task);
        let envelope = Arc::new(envelope);
        let mut set = tokio::task::JoinSet::new();
        for (idx, target) in targets.iter().enumerate() {
            let task = Arc::clone(&task);
            let envelope = Arc::clone(&envelope);
            let this = self.clone();
            let peer = target.peer_id;
            set.spawn(async move {
                let replica = if peer == this.local_peer_id {
                    this.local_replica(&task, &envelope).await
                } else {
                    this.remote_replica(&task, peer, &envelope).await
                };
                (idx, replica)
            });
        }
        let mut slots: Vec<Option<ReplicaResult>> = (0..targets.len()).map(|_| None).collect();
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((idx, replica)) => slots[idx] = Some(replica),
                Err(e) => {
                    return Err(DispatchError::Integrity(IntegrityError::MetricFailed {
                        metric: "-".into(),
                        reason: format!("replica task panicked or was cancelled: {e}"),
                    }))
                }
            }
        }
        let replicas: Vec<ReplicaResult> = slots.into_iter().flatten().collect();

        let acceptance = self.verifier.accept(&task, &envelope, replicas).await?;
        Ok(DispatchResult {
            chosen: targets[acceptance.chosen].clone(),
            output: acceptance.output,
            policy_hash: envelope.hash(),
            replicas: acceptance.reports,
            pair_agreement: acceptance.pair_agreement,
        })
    }

    /// One replica on the local kernel: exactly one invocation, no policy
    /// applied (verification happens in the acceptance pipeline).
    async fn local_replica(&self, task: &OneShotTask, envelope: &PolicyEnvelope) -> ReplicaResult {
        let outcome = self
            .kernel
            .invoke(&task.plugin, &task.input, task.timeout_ms)
            .await
            .map(|bytes| ReplicaBytes {
                bytes,
                observed_policy_hash: envelope.recompute_hash(),
            })
            .map_err(DispatchError::from);
        ReplicaResult {
            peer: self.local_peer_id,
            remote: false,
            outcome,
        }
    }

    /// One replica on `peer`. Only called when a transport is configured.
    async fn remote_replica(
        &self,
        task: &OneShotTask,
        peer: PeerId,
        envelope: &PolicyEnvelope,
    ) -> ReplicaResult {
        let outcome = match &self.remote {
            Some(remote) => {
                remote
                    .dispatch_sealed(task, peer, envelope)
                    .await
                    .map(|r| ReplicaBytes {
                        bytes: r.output,
                        observed_policy_hash: r.observed_policy_hash,
                    })
            }
            None => Err(DispatchError::RemoteNotImplemented {
                peer,
                reason: "no mesh transport configured".into(),
            }),
        };
        ReplicaResult {
            peer,
            remote: true,
            outcome,
        }
    }
}
