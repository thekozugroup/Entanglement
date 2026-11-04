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
//!
//! # Layer-2 spot-checks (spec §7.5)
//!
//! With [`Dispatcher::with_spot_checks`], an accepted `Deterministic` or
//! `SemanticEquivalent` task is, with the configured probability, re-run in
//! the background on an executor that produced none of its replicas and
//! compared with the accepted output; see [`crate::spot_check`]. The result
//! is returned first and never changed by the check
//! ([`DispatchResult::spot_check`] says what was decided).

use crate::{
    integrity::{
        canonical_operands, replica_count, IntegrityVerifier, OutputSizeExceededWarning,
        ReplicaBytes, ReplicaReport, ReplicaResult, ReplicaStatus,
    },
    placement::{choose, rank, PlacementChoice, PlacementError},
    remote::RemoteDispatch,
    reputation::ReputationReason,
    spot_check::{
        shuffle, Exemption, SkipReason, SpotCheck, SpotCheckConfig, SpotCheckHandle,
        SpotCheckRecord, SpotCheckVerdict, SpotChecker, TieBreak, MAX_EXECUTORS,
    },
    wire::RemoteErrorCode,
    work_unit::{PolicyEnvelope, PolicyHash},
    worker::{WorkerInfo, WorkerPool},
};
use entangle_observability::{catalog, Registry};
use entangle_runtime::{IntegrityError, Kernel};
use entangle_types::{
    errors::EntangleError,
    peer_id::PeerId,
    task::{IntegrityPolicy, OneShotTask, PolicyKind},
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::Instrument as _;

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
    /// [`EntangleError::OutputSizeExceeded`]
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
    /// What was decided about the Layer-2 spot-check of this result (spec
    /// §7.5). A scheduled check runs after this result is returned and
    /// never changes it; await its verdict through
    /// [`SpotCheck::handle`].
    pub spot_check: SpotCheck,
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
    /// Metrics sink; `None` until [`Dispatcher::with_metrics`].
    metrics: Option<Registry>,
    /// Tasks inside [`Dispatcher::dispatch_one_shot`] right now.
    inflight: Arc<AtomicU64>,
    /// Layer-2 spot-checks; `None` (off) until
    /// [`Dispatcher::with_spot_checks`].
    spot: Option<Arc<SpotChecker>>,
}

/// Metric label for the outcome of a remote replica.
fn remote_outcome<T>(result: &Result<T, DispatchError>) -> String {
    match result {
        Ok(_) => "ok".to_owned(),
        Err(DispatchError::RemoteTransport { .. }) => "transport_error".to_owned(),
        // `RemoteErrorCode` labels are a closed set (kebab-case).
        Err(DispatchError::RemoteRejected { code, .. }) => {
            format!("rejected_{}", code.as_str().replace('-', "_"))
        }
        Err(DispatchError::OutputSizeExceeded(_)) => "output_too_large".to_owned(),
        Err(_) => "error".to_owned(),
    }
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
            metrics: None,
            inflight: Arc::new(AtomicU64::new(0)),
            spot: None,
        }
    }

    /// Turn on Layer-2 spot-checks (spec §7.5) with `config`: an accepted
    /// `Deterministic` or `SemanticEquivalent` task is re-run, with
    /// probability `config.probability`, on an executor that produced none
    /// of its replicas, at most `config.max_concurrent` at a time. See
    /// [`crate::spot_check`]. A dispatcher without this never spot-checks.
    #[must_use]
    pub fn with_spot_checks(mut self, config: SpotCheckConfig) -> Self {
        let checker = Arc::new(SpotChecker::new(config));
        if let Some(registry) = &self.metrics {
            register_spot_gauge(registry, &checker);
        }
        self.spot = Some(checker);
        self
    }

    /// The spot-check state (configuration, running totals, recent
    /// verdicts), when spot-checks are configured.
    pub fn spot_checks(&self) -> Option<&Arc<SpotChecker>> {
        self.spot.as_ref()
    }

    /// Record this dispatcher's activity into `registry`.
    ///
    /// Counts remote dispatches by outcome and integrity verdicts by policy
    /// kind and outcome, counts oversized replica outputs, and exposes (at
    /// scrape time) the in-flight task count, the live-worker count and the
    /// number of peers in each reputation tier. There is no scheduler queue:
    /// dispatch is immediate, so *in-flight* is the saturation signal.
    #[must_use]
    pub fn with_metrics(mut self, registry: Registry) -> Self {
        self.verifier.set_telemetry(registry.clone());
        let inflight = Arc::clone(&self.inflight);
        let workers = self.workers.clone();
        let ttl = self.worker_ttl;
        let reputation = Arc::clone(self.verifier.reputation());
        registry.register_collector(move |r| {
            r.set_gauge(
                catalog::names::SCHEDULER_INFLIGHT,
                "Tasks the dispatcher is executing right now",
                &[],
                inflight.load(Ordering::Relaxed) as f64,
            );
            r.set_gauge(
                catalog::names::SCHEDULER_WORKERS,
                "Live workers in the scheduler pool",
                &[],
                workers.live(ttl).len() as f64,
            );
            // Rebuilt each scrape so a peer that left a tier does not leave
            // a stale count behind.
            r.clear_family(catalog::names::REPUTATION_PEERS);
            for (kind, tier, n) in reputation.tier_counts() {
                r.set_gauge(
                    catalog::names::REPUTATION_PEERS,
                    "Peers per reputation tier and integrity policy kind",
                    &[("policy", kind.as_str()), ("tier", tier.as_str())],
                    n as f64,
                );
            }
        });
        if let Some(checker) = &self.spot {
            register_spot_gauge(&registry, checker);
        }
        self.metrics = Some(registry);
        self
    }

    /// Tasks executing inside the dispatcher right now.
    pub fn inflight(&self) -> u64 {
        self.inflight.load(Ordering::Relaxed)
    }

    /// The remote dispatch client, if a transport is configured.
    pub fn remote(&self) -> Option<&Arc<RemoteDispatch>> {
        self.remote.as_ref()
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
        let kind = task.integrity.kind();
        let span = tracing::info_span!(
            "task.dispatch",
            plugin = %task.plugin,
            policy = %kind,
            input_bytes = task.input.len() as u64,
        );
        self.inflight.fetch_add(1, Ordering::Relaxed);
        let result = self.dispatch_checked(task).instrument(span).await;
        self.inflight.fetch_sub(1, Ordering::Relaxed);
        if let Some(reg) = &self.metrics {
            let outcome = match &result {
                Ok(_) => "accepted",
                Err(DispatchError::OutputSizeExceeded(_)) => "output_size_exceeded",
                Err(DispatchError::Integrity(_)) => "rejected",
                Err(_) => "failed",
            };
            catalog::integrity_verdict(reg, kind.as_str(), outcome);
        }
        result
    }

    async fn dispatch_checked(&self, task: OneShotTask) -> Result<DispatchResult, DispatchError> {
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
        let spot_check = self.schedule_spot_check(
            &task,
            &envelope,
            &acceptance.output,
            &acceptance.reports,
            Vec::new(),
        );
        Ok(DispatchResult {
            chosen,
            output: acceptance.output,
            policy_hash: envelope.hash(),
            replicas: acceptance.reports,
            pair_agreement: acceptance.pair_agreement,
            spot_check,
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
                Err(e) => tracing::error!(error = %e, "replica task did not complete"),
            }
        }
        // A replica whose task panicked is a failed replica, not a reason to
        // abandon the others.
        let replicas: Vec<ReplicaResult> = slots
            .into_iter()
            .zip(&targets)
            .map(|(slot, target)| {
                slot.unwrap_or_else(|| ReplicaResult {
                    peer: target.peer_id,
                    remote: target.peer_id != self.local_peer_id,
                    outcome: Err(DispatchError::RemoteTransport {
                        peer: target.peer_id,
                        reason: "replica task did not complete (panicked or cancelled)".into(),
                    }),
                })
            })
            .collect();

        // A local replica the remote majority outvotes is a spot-check
        // re-run already in hand (see `schedule_spot_check`); a metric needs
        // its bytes, which acceptance consumes.
        let local_outputs: Vec<(usize, Vec<u8>)> =
            if self.spot.as_ref().is_some_and(|c| c.enabled())
                && kind == PolicyKind::SemanticEquivalent
            {
                replicas
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| !r.remote)
                    .filter_map(|(i, r)| r.outcome.as_ref().ok().map(|o| (i, o.bytes.clone())))
                    .collect()
            } else {
                Vec::new()
            };
        let acceptance = self.verifier.accept(&task, &envelope, replicas).await?;
        let spot_check = self.schedule_spot_check(
            &task,
            &envelope,
            &acceptance.output,
            &acceptance.reports,
            local_outputs,
        );
        Ok(DispatchResult {
            chosen: targets[acceptance.chosen].clone(),
            output: acceptance.output,
            policy_hash: envelope.hash(),
            replicas: acceptance.reports,
            pair_agreement: acceptance.pair_agreement,
            spot_check,
        })
    }

    /// Decide the Layer-2 spot-check of an accepted result and, when it is
    /// sampled and a slot and an executor are free, start it in the
    /// background (see [`crate::spot_check`]).
    ///
    /// `local_outputs` are the outputs of the replicas this node's kernel
    /// ran, by replica index (`SemanticEquivalent` only: a hash comparison
    /// needs just the reports).
    fn schedule_spot_check(
        &self,
        task: &OneShotTask,
        envelope: &PolicyEnvelope,
        output: &[u8],
        reports: &[ReplicaReport],
        mut local_outputs: Vec<(usize, Vec<u8>)>,
    ) -> SpotCheck {
        let Some(checker) = self.spot.as_ref().filter(|c| c.enabled()) else {
            return SpotCheck::Disabled;
        };
        let kind = envelope.policy().kind();
        if !matches!(
            kind,
            PolicyKind::Deterministic | PolicyKind::SemanticEquivalent
        ) {
            return SpotCheck::Exempt(Exemption::Policy);
        }
        let behind_output = |r: &ReplicaReport| {
            matches!(r.status, ReplicaStatus::Canonical | ReplicaStatus::Agreed)
        };
        if reports.iter().any(|r| !r.remote && behind_output(r)) {
            // This node's own kernel already produced (or agreed with) it.
            return SpotCheck::Exempt(Exemption::ReproducedLocally);
        }
        if !checker.sample() {
            return SpotCheck::NotSampled;
        }
        // This node's own kernel ran a replica and the remote majority
        // outvoted it: the trusted kernel's output, already in hand, is the
        // re-run — nothing needs to run again, and no other executor is
        // needed.
        let seed = reports
            .iter()
            .enumerate()
            .filter(|(_, r)| !r.remote && r.status == ReplicaStatus::Disagreed)
            .find_map(|(i, r)| {
                let bytes = match kind {
                    PolicyKind::SemanticEquivalent => {
                        let at = local_outputs.iter().position(|(j, _)| *j == i)?;
                        Some(local_outputs.swap_remove(at).1)
                    }
                    _ => None,
                };
                Some(Rerun {
                    executor: r.peer,
                    remote: false,
                    blake3: r.output_blake3?,
                    bytes,
                })
            });
        drop(local_outputs);
        let replicas: Vec<PeerId> = reports.iter().map(|r| r.peer).collect();
        let executors = self.spot_check_executors(task, kind, &replicas);
        if seed.is_none() && executors.is_empty() {
            checker.note_no_checker();
            self.count_spot_check(kind, "skipped_no_checker");
            tracing::info!(
                target: crate::integrity::TELEMETRY_TARGET,
                event = "SpotCheckSkipped",
                reason = "no-checker",
                task_id = %task.id,
                plugin = %task.plugin,
                policy = %kind,
                "spot-check sampled but not run: no executor other than the task's replicas \
                 can run it"
            );
            return SpotCheck::Skipped(SkipReason::NoChecker);
        }
        let Some(permit) = checker.try_begin() else {
            self.count_spot_check(kind, "skipped_saturated");
            tracing::info!(
                target: crate::integrity::TELEMETRY_TARGET,
                event = "SpotCheckSkipped",
                reason = "saturated",
                task_id = %task.id,
                plugin = %task.plugin,
                policy = %kind,
                in_flight = checker.in_flight(),
                "spot-check sampled but not run: the concurrency bound is reached"
            );
            return SpotCheck::Skipped(SkipReason::Saturated);
        };
        let implicated: Vec<PeerId> = reports
            .iter()
            .filter(|r| r.remote && behind_output(r))
            .map(|r| r.peer)
            .collect();
        let accepted = Accepted {
            blake3: *blake3::hash(output).as_bytes(),
            // Only a metric needs the bytes; a hash comparison keeps 32.
            bytes: matches!(kind, PolicyKind::SemanticEquivalent).then(|| output.to_vec()),
        };
        let (tx, handle) = SpotCheckHandle::channel();
        let span = tracing::info_span!(
            "integrity.spot_check",
            task_id = %task.id,
            plugin = %task.plugin,
            policy = %kind,
            // Known once an executor has produced the re-run.
            checker = tracing::field::Empty,
            checker_remote = tracing::field::Empty,
        );
        let this = self.clone();
        let checker = Arc::clone(checker);
        let task = task.clone();
        let envelope = envelope.clone();
        tokio::spawn(
            async move {
                // Held for the re-run and comparison: the concurrency bound.
                let slot = permit;
                let record = Arc::new(
                    this.run_spot_check(&task, &envelope, accepted, executors, seed, implicated)
                        .await,
                );
                // The slot is free before the verdict is visible, so a
                // caller woken by it sees the check as no longer running.
                drop(slot);
                record.emit_if_mismatch();
                this.count_spot_check(kind, record.verdict.label());
                tracing::debug!(verdict = record.verdict.label(), "spot-check finished");
                checker.record(Arc::clone(&record));
                tx.send_replace(Some(record));
            }
            .instrument(span),
        );
        SpotCheck::Scheduled(handle)
    }

    /// Who may re-run a spot-checked task, in the order they are asked:
    /// this node's own kernel first — the one executor the submitter can
    /// trust — if it has the plugin loaded and is not itself among the
    /// `replicas`; then the live remote workers that ran none of them, fit
    /// the task's resources and are not excluded for `kind`, in **random**
    /// order (rank is self-advertised, so a worker could otherwise place
    /// itself to be the checker every time) — at most [`MAX_EXECUTORS`].
    /// Empty: nobody.
    fn spot_check_executors(
        &self,
        task: &OneShotTask,
        kind: PolicyKind,
        replicas: &[PeerId],
    ) -> Vec<(PeerId, bool)> {
        let mut out = Vec::new();
        if !replicas.contains(&self.local_peer_id)
            && self.kernel.plugin_world(&task.plugin) == Some("plugin")
        {
            out.push((self.local_peer_id, false));
        }
        if self.remote.is_some() {
            let live = self.workers.live(self.worker_ttl);
            if let Ok(ranked) = rank(&live, &task.resources) {
                let mut remote: Vec<(PeerId, bool)> = ranked
                    .into_iter()
                    .filter(|c| {
                        c.peer_id != self.local_peer_id
                            && !replicas.contains(&c.peer_id)
                            && self.verifier.reputation().is_eligible(&c.peer_id, kind)
                    })
                    .map(|c| (c.peer_id, true))
                    .collect();
                shuffle(&mut remote);
                out.extend(remote);
            }
        }
        out.truncate(MAX_EXECUTORS);
        out
    }

    /// Re-run `task` — or take `seed`, a re-run already in hand — and
    /// compare with the accepted output. The `executors` are asked in turn
    /// until one produces a comparable output (one that cannot run the task
    /// does not end the check).
    ///
    /// One re-run never outweighs the replicas on its own word: a re-run
    /// that does not reproduce the accepted output is decisive only when it
    /// is a `Deterministic` re-run on this node's own kernel. Otherwise the
    /// next executor breaks the tie — if it reproduces the accepted output,
    /// the checker loses ([`ReputationReason::SpotCheckDissent`], when
    /// remote) and the verdict is `Confirmed`; if it reproduces the
    /// checker's, the mismatch is corroborated; with no tie-breaker, or
    /// three different answers, nobody is blamed (`Inconclusive`).
    ///
    /// On a mismatch the `implicated` replicas lose reputation; on a
    /// confirmation they are credited. A remote executor that breaks the
    /// size or policy-hash guard loses reputation too.
    async fn run_spot_check(
        &self,
        task: &OneShotTask,
        envelope: &PolicyEnvelope,
        accepted: Accepted,
        executors: Vec<(PeerId, bool)>,
        seed: Option<Rerun>,
        implicated: Vec<PeerId>,
    ) -> SpotCheckRecord {
        let kind = envelope.policy().kind();
        let reputation = self.verifier.reputation();
        let (first, first_remote) = seed
            .as_ref()
            .map(|r| (r.executor, r.remote))
            .or_else(|| executors.first().copied())
            .unwrap_or((self.local_peer_id, false));
        let mut record = SpotCheckRecord {
            task_id: task.id,
            plugin: task.plugin.clone(),
            policy: kind,
            policy_hash: envelope.hash(),
            checker: first,
            checker_remote: first_remote,
            accepted_blake3: accepted.blake3,
            rerun_blake3: None,
            distance: None,
            implicated,
            penalised: Vec::new(),
            reused_replica: seed.is_some(),
            unavailable: Vec::new(),
            tie_breaker: None,
            credited: Vec::new(),
            verdict: SpotCheckVerdict::Confirmed,
        };
        let mut executors = executors.into_iter();
        let out = match seed {
            Some(rerun) => rerun,
            None => match self
                .next_rerun(task, envelope, &mut executors, &mut record)
                .await
            {
                Some(rerun) => rerun,
                None => {
                    if let Some((executor, _)) = record.unavailable.last() {
                        record.checker = *executor;
                        record.checker_remote = *executor != self.local_peer_id;
                    }
                    record.verdict = SpotCheckVerdict::Inconclusive(format!(
                        "no executor produced a comparable re-run ({})",
                        describe_unavailable(&record.unavailable)
                    ));
                    return record;
                }
            },
        };
        record.checker = out.executor;
        record.checker_remote = out.remote;
        let span = tracing::Span::current();
        span.record("checker", tracing::field::display(out.executor));
        span.record("checker_remote", out.remote);
        record.rerun_blake3 = Some(out.blake3);
        let accepted_view = (
            accepted.bytes.as_deref().unwrap_or_default(),
            &accepted.blake3,
        );
        let (agrees, distance) = match self.agreement(envelope, accepted_view, out.view()).await {
            Ok(a) => a,
            Err(e) => {
                record.verdict = SpotCheckVerdict::Inconclusive(format!(
                    "the metric could not compare the re-run with the accepted output: {e}"
                ));
                return record;
            }
        };
        record.distance = distance;
        if agrees {
            self.credit(&mut record, kind);
            return record;
        }
        let mut detail = match (envelope.policy(), distance) {
            (IntegrityPolicy::SemanticEquivalent { threshold, .. }, Some(d)) => format!(
                "returned an output at metric distance {d} from the accepted one (threshold \
                 {threshold})"
            ),
            _ => format!(
                "returned output with BLAKE3 {}, not the accepted {}",
                hex::encode(out.blake3),
                hex::encode(accepted.blake3)
            ),
        };

        // A `Deterministic` re-run on this node's own kernel is decisive: the
        // submitter trusts its kernel, and the output is byte-exact. Any
        // other contradiction needs an independent tie-breaker before anyone
        // is blamed (a remote checker may lie; a semantic re-run may be an
        // honest outlier).
        let decisive = !out.remote && kind == PolicyKind::Deterministic;
        if !decisive {
            let Some(tie) = self
                .next_rerun(task, envelope, &mut executors, &mut record)
                .await
            else {
                record.verdict = SpotCheckVerdict::Inconclusive(format!(
                    "the re-run on {} {detail}, and no independent executor was left to break \
                     the tie: one re-run does not outweigh the replicas, so nobody is blamed",
                    out.executor
                ));
                return record;
            };
            let with_accepted = self.agreement(envelope, accepted_view, tie.view()).await;
            let with_checker = self.agreement(envelope, out.view(), tie.view()).await;
            let (Ok((agrees_with_accepted, _)), Ok((agrees_with_checker, _))) =
                (with_accepted, with_checker)
            else {
                record.verdict = SpotCheckVerdict::Inconclusive(format!(
                    "the metric could not compare the tie-breaking re-run on {}",
                    tie.executor
                ));
                return record;
            };
            record.tie_breaker = Some(TieBreak {
                executor: tie.executor,
                remote: tie.remote,
                rerun_blake3: tie.blake3,
                agrees_with_accepted,
                agrees_with_checker,
            });
            if agrees_with_accepted {
                // The accepted output is reproduced after all: the checker
                // lost the tie (unless the tie-breaker agrees with it too).
                if !agrees_with_checker && out.remote {
                    reputation.penalize(&out.executor, kind, ReputationReason::SpotCheckDissent);
                    record.penalised.push(out.executor);
                }
                self.credit(&mut record, kind);
                return record;
            }
            if !agrees_with_checker {
                record.verdict = SpotCheckVerdict::Inconclusive(format!(
                    "the re-run on {} {detail}, and the tie-breaking re-run on {} agrees with \
                     neither: nobody is blamed",
                    out.executor, tie.executor
                ));
                return record;
            }
            detail.push_str(&format!(
                "; corroborated by an independent re-run on {}",
                tie.executor
            ));
        }
        for peer in &record.implicated {
            reputation.penalize(peer, kind, ReputationReason::SpotCheckMismatch);
        }
        record.penalised.extend(record.implicated.iter().copied());
        record.verdict = SpotCheckVerdict::Mismatch(IntegrityError::SpotCheckMismatch {
            task: task.id.to_string(),
            checker: out.executor.to_hex(),
            detail,
            agreed: record.implicated.len(),
        });
        record
    }

    /// The accepted output stood up to the check: credit the replicas behind
    /// it, so standing rises with confirmations as it falls with failures.
    fn credit(&self, record: &mut SpotCheckRecord, kind: PolicyKind) {
        for peer in &record.implicated {
            self.verifier.reputation().record_correct(peer, kind);
        }
        record.credited = record.implicated.clone();
        record.verdict = SpotCheckVerdict::Confirmed;
    }

    /// Whether two outputs agree under the task's policy — identical bytes
    /// always do (no metric is run); `SemanticEquivalent` compares in
    /// acceptance's canonical pair order, a metric may be asymmetric — and
    /// the metric distance when one was computed. `Err`: the metric could
    /// not compare them.
    async fn agreement(
        &self,
        envelope: &PolicyEnvelope,
        x: (&[u8], &[u8; 32]),
        y: (&[u8], &[u8; 32]),
    ) -> Result<(bool, Option<f64>), IntegrityError> {
        if x.1 == y.1 {
            return Ok((true, None));
        }
        match envelope.policy() {
            IntegrityPolicy::SemanticEquivalent {
                metric, threshold, ..
            } => {
                let (a, b) = canonical_operands(x, y);
                let d = self.verifier.metrics().compare(metric, a, b).await?;
                Ok((d < *threshold, Some(d)))
            }
            _ => Ok((false, None)),
        }
    }

    /// Ask `executors` in turn to re-run `task` until one produces a
    /// comparable output; each that does not is listed in
    /// `record.unavailable` with why. `None` when none of them did.
    async fn next_rerun(
        &self,
        task: &OneShotTask,
        envelope: &PolicyEnvelope,
        executors: &mut impl Iterator<Item = (PeerId, bool)>,
        record: &mut SpotCheckRecord,
    ) -> Option<Rerun> {
        for (executor, remote) in executors.by_ref() {
            match self.rerun(task, envelope, executor, remote, record).await {
                Ok(rerun) => return Some(rerun),
                Err(why) => {
                    tracing::debug!(
                        %executor,
                        why = %why,
                        "spot-check executor produced nothing comparable; trying the next"
                    );
                    record.unavailable.push((executor, why));
                }
            }
        }
        None
    }

    /// Run `task` once more on `executor` and pass the result through the
    /// guards a replica passes (output size, then the echoed policy hash).
    /// `Err` (why) when it produced nothing comparable; a remote executor
    /// that broke a guard is penalised and listed in `record.penalised`.
    async fn rerun(
        &self,
        task: &OneShotTask,
        envelope: &PolicyEnvelope,
        executor: PeerId,
        remote: bool,
        record: &mut SpotCheckRecord,
    ) -> Result<Rerun, String> {
        let kind = envelope.policy().kind();
        let reputation = self.verifier.reputation();
        let replica = if remote {
            self.remote_replica(task, executor, envelope).await
        } else {
            self.local_replica(task, envelope).await
        };
        let declared = task.max_output_bytes;
        let oversized = match &replica.outcome {
            Ok(out) if out.bytes.len() as u64 > declared => Some(out.bytes.len() as u64),
            Err(DispatchError::OutputSizeExceeded(EntangleError::OutputSizeExceeded {
                actual,
                ..
            })) => Some(*actual),
            _ => None,
        };
        // INV-INT-2, as for a replica: above the metric, and terminal.
        if let Some(actual) = oversized {
            OutputSizeExceededWarning {
                peer_id: executor,
                declared,
                actual,
            }
            .emit();
            if let Some(reg) = &self.metrics {
                catalog::output_size_exceeded(reg);
            }
            if remote {
                reputation.penalize(&executor, kind, ReputationReason::OversizedOutput);
                record.penalised.push(executor);
            }
            return Err(format!(
                "the re-run returned {actual} bytes, over max_output_bytes {declared}"
            ));
        }
        let out = replica
            .outcome
            .map_err(|e| format!("the re-run did not complete: {e}"))?;
        // INV-INT-1, as for a replica.
        if out.observed_policy_hash != envelope.hash() {
            if remote {
                reputation.penalize(&executor, kind, ReputationReason::PolicyHashMismatch);
                record.penalised.push(executor);
            }
            return Err(format!(
                "the re-run reported policy hash {}, not the dispatched {}",
                out.observed_policy_hash,
                envelope.hash()
            ));
        }
        let blake3 = *blake3::hash(&out.bytes).as_bytes();
        Ok(Rerun {
            executor,
            remote,
            blake3,
            // Only a metric needs the bytes.
            bytes: (kind == PolicyKind::SemanticEquivalent).then_some(out.bytes),
        })
    }

    fn count_spot_check(&self, kind: PolicyKind, outcome: &str) {
        if let Some(reg) = &self.metrics {
            catalog::spot_check(reg, kind.as_str(), outcome);
        }
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
                let (raw, transport) = remote.dispatch_sealed_routed(task, peer, envelope).await;
                if let Some(reg) = &self.metrics {
                    catalog::remote_dispatch(
                        reg,
                        &remote_outcome(&raw),
                        crate::transport::TransportKind::label(transport),
                    );
                }
                raw.map(|r| ReplicaBytes {
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

/// `unavailable` as one line for a verdict.
fn describe_unavailable(unavailable: &[(PeerId, String)]) -> String {
    if unavailable.is_empty() {
        return "none was available".to_owned();
    }
    unavailable
        .iter()
        .map(|(peer, why)| format!("{peer}: {why}"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// One spot-check re-run that produced a comparable output.
struct Rerun {
    /// Who ran it.
    executor: PeerId,
    /// Whether that is another node.
    remote: bool,
    /// BLAKE3 of its output.
    blake3: [u8; 32],
    /// Its bytes, for a metric comparison (`SemanticEquivalent` only).
    bytes: Option<Vec<u8>>,
}

impl Rerun {
    /// `(bytes, BLAKE3)` for a comparison.
    fn view(&self) -> (&[u8], &[u8; 32]) {
        (self.bytes.as_deref().unwrap_or_default(), &self.blake3)
    }
}

/// The accepted output, as much of it as a spot-check needs.
struct Accepted {
    blake3: [u8; 32],
    /// The bytes, for a metric comparison (`SemanticEquivalent` only).
    bytes: Option<Vec<u8>>,
}

/// Publish the in-flight spot-check count at scrape time.
fn register_spot_gauge(registry: &Registry, checker: &Arc<SpotChecker>) {
    let checker = Arc::clone(checker);
    registry.register_collector(move |r| {
        r.set_gauge(
            catalog::names::SPOT_CHECKS_INFLIGHT,
            "Layer-2 spot-checks running right now",
            &[],
            checker.in_flight() as f64,
        );
    });
}
