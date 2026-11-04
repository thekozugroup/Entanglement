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
//! # Failure handling (spec §7.6)
//!
//! Every remote replica runs as a **slot** ([`crate::retry`]): an attempt
//! that fails in a way that says nothing about the task — the worker
//! crashed, the peer was lost, or the transport failed after the request
//! was sent — is retried per the task's [`RetryPolicy`] on another eligible
//! worker, never one that holds a replica of the same task; and with
//! [`Dispatcher::with_speculation`] a slow attempt gets a backup copy on
//! another worker, the first valid result winning and the other copy being
//! cancelled. Every attempt is listed in [`DispatchResult::attempts`].
//!
//! [`RetryPolicy`]: entangle_types::task::RetryPolicy
//!
//! # Layer-2 spot-checks (spec §7.5)
//!
//! With [`Dispatcher::with_spot_checks`], an accepted `Deterministic` or
//! `SemanticEquivalent` task is, with the configured probability, re-run in
//! the background on an executor that produced none of its replicas and
//! compared with the accepted output; see [`crate::spot_check`]. The result
//! is returned first and never changed by the check
//! ([`DispatchResult::spot_check`] says what was decided).

use crate::retry::{DurationHistory, RetryCause, SpeculationConfig};
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
    task::{IntegrityPolicy, OneShotTask, PolicyKind, TaskId},
};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::Instrument as _;

/// How long a `Cancel` control frame to the losing copy of a speculative
/// pair may take before it is given up on (it is best effort: the losing
/// copy's request is dropped either way).
pub const CANCEL_TIMEOUT: Duration = Duration::from_secs(2);

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
    /// The task was refused at submit time by [`crate::submit`]: a
    /// `Deterministic` task for a plugin that declares non-determinism
    /// (`ENTANGLE-E0470`), or a workload preset that cannot apply
    /// (`E0471`–`E0473`). Nothing was placed or sent.
    #[error("{0}")]
    Submit(#[from] crate::submit::SubmitError),
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
    /// Every attempt made, per replica, in the order they started: the
    /// first attempt of each replica, its retries and any speculative
    /// backup copy (see [`crate::retry`]).
    pub attempts: Vec<Attempt>,
    /// BLAKE3 digest of the component artifact that produced the returned
    /// output, when known (spec §7.5 `TrustedExecutor`: "the work unit's
    /// signed component CID is recorded with the result for after-the-fact
    /// audit"): this node's own loaded artifact when it ran the task, the
    /// executor's report when a `TrustedExecutor` task ran remotely (other
    /// policies do not ask remote executors for it). The remote value is
    /// the executor's claim — attributable to it through the transport's
    /// authentication, not independently verifiable.
    pub executed_component: Option<[u8; 32]>,
}

/// Why an attempt was started.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AttemptKind {
    /// The replica's first attempt.
    First,
    /// A retry after the previous attempt failed with this cause.
    Retry(RetryCause),
    /// A speculative backup copy of a slow attempt.
    Speculative,
}

impl AttemptKind {
    /// Stable label: `first`, `retry`, `speculative`.
    pub const fn label(self) -> &'static str {
        match self {
            Self::First => "first",
            Self::Retry(_) => "retry",
            Self::Speculative => "speculative",
        }
    }
}

/// What became of an attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// Its result is the replica's result (acceptance then judged it).
    Used,
    /// It failed; why.
    Failed(String),
    /// Another copy of the replica produced a valid result first; this one
    /// was cancelled (a `Cancel` control frame was sent to its worker).
    Cancelled,
}

impl AttemptOutcome {
    /// Stable label: `used`, `failed`, `cancelled`.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Used => "used",
            Self::Failed(_) => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// One attempt at one replica, for audit ([`DispatchResult::attempts`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    /// The replica (slot) it belongs to, in dispatch order.
    pub replica: usize,
    /// Who ran it.
    pub peer: PeerId,
    /// Whether that is another node.
    pub remote: bool,
    /// The task id it was sent under: the task's own for a first attempt,
    /// a fresh one for a retry or a backup copy.
    pub task_id: TaskId,
    /// Why it was started.
    pub kind: AttemptKind,
    /// What became of it.
    pub outcome: AttemptOutcome,
    /// How long it ran, until it answered or was cancelled.
    pub elapsed: Duration,
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
    /// When to start backup copies of slow attempts (off by default).
    speculation: SpeculationConfig,
    /// Durations of recent successful attempts, per plugin.
    history: Arc<DurationHistory>,
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
    /// keyring and refuses metric packages the kernel has disabled
    /// ([`IntegrityVerifier::for_kernel`]); replace it with
    /// [`Dispatcher::with_verifier`].
    pub fn new(workers: WorkerPool, kernel: Arc<Kernel>, local_peer_id: PeerId) -> Self {
        let verifier = Arc::new(IntegrityVerifier::for_kernel(&kernel, local_peer_id));
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
            speculation: SpeculationConfig::Off,
            history: Arc::new(DurationHistory::new()),
        }
    }

    /// Start speculative backup copies of slow remote attempts (spec §7.6;
    /// see [`SpeculationConfig`]). Off by default.
    #[must_use]
    pub fn with_speculation(mut self, config: SpeculationConfig) -> Self {
        self.speculation = config;
        self
    }

    /// The speculation settings in force.
    pub fn speculation(&self) -> SpeculationConfig {
        self.speculation
    }

    /// Durations of recent successful attempts, per plugin (the input of
    /// [`SpeculationConfig::MedianMultiple`]).
    pub fn durations(&self) -> &Arc<DurationHistory> {
        &self.history
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
                Err(DispatchError::Integrity(_) | DispatchError::Submit(_)) => "rejected",
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
        // §7.5: `Deterministic` is refused for a plugin whose manifest (as
        // this node's kernel loaded it) declares non-determinism. Executors
        // check their own copy as well.
        crate::submit::check_determinism(&self.kernel, &task.plugin, &task.integrity)?;

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

        let mut chosen = chosen;
        let (replica, attempts) = if run_local {
            // Enforce the task's policy on the local kernel (TrustedExecutor
            // allowlist, Deterministic { 0 | 1 } as a single invocation).
            let started = Instant::now();
            let component = self.local_component(&task.plugin);
            let outcome = self
                .kernel
                .invoke_with_integrity(&task, self.local_peer_id)
                .await
                .map(|bytes| ReplicaBytes {
                    bytes,
                    observed_policy_hash: envelope.recompute_hash(),
                    component,
                })
                .map_err(DispatchError::from);
            let replica = ReplicaResult {
                peer: self.local_peer_id,
                remote: false,
                outcome,
            };
            let attempt = local_attempt(0, &replica, task.id, started.elapsed());
            (replica, vec![attempt])
        } else {
            tracing::debug!(
                peer = %chosen.peer_id,
                plugin = %task.plugin,
                "dispatching task to remote peer"
            );
            let ctx = Arc::new(SlotCtx {
                threshold: self.speculation.threshold(&task.plugin, &self.history),
                deadline: Instant::now() + Duration::from_millis(task.timeout_ms),
                task: Arc::new(task.clone()),
                envelope: Arc::new(envelope.clone()),
                replicated: false,
                holders: Arc::new(parking_lot::Mutex::new(HashSet::from([chosen.peer_id]))),
            });
            let slot = self.run_slot(ctx, 0, chosen.peer_id).await;
            if slot.replica.peer != chosen.peer_id {
                chosen = PlacementChoice {
                    peer_id: slot.replica.peer,
                    score: chosen.score,
                    reason: format!(
                        "{} — failed over from {} (see attempts)",
                        chosen.reason, chosen.peer_id
                    ),
                };
            }
            (slot.replica, slot.attempts)
        };

        let acceptance = self
            .verifier
            .accept(&task, &envelope, vec![replica])
            .await?;
        let executed_component = acceptance
            .reports
            .get(acceptance.chosen)
            .and_then(|r| r.component);
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
            attempts,
            executed_component,
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
        // Remote replicas run as slots (retries, backup copies) that share
        // one set of replica holders, so no two replicas — first attempts,
        // retries or backups — ever run on the same worker.
        let task = Arc::new(task);
        let envelope = Arc::new(envelope);
        let ctx = Arc::new(SlotCtx {
            threshold: self.speculation.threshold(&task.plugin, &self.history),
            deadline: Instant::now() + Duration::from_millis(task.timeout_ms),
            task: Arc::clone(&task),
            envelope: Arc::clone(&envelope),
            replicated: true,
            holders: Arc::new(parking_lot::Mutex::new(
                targets.iter().map(|t| t.peer_id).collect(),
            )),
        });
        let mut set = tokio::task::JoinSet::new();
        for (idx, target) in targets.iter().enumerate() {
            let task = Arc::clone(&task);
            let envelope = Arc::clone(&envelope);
            let ctx = Arc::clone(&ctx);
            let this = self.clone();
            let peer = target.peer_id;
            let span = tracing::Span::current();
            set.spawn(
                async move {
                    let slot = if peer == this.local_peer_id {
                        let started = Instant::now();
                        let replica = this.local_replica(&task, &envelope).await;
                        let attempt = local_attempt(idx, &replica, task.id, started.elapsed());
                        SlotResult {
                            replica,
                            attempts: vec![attempt],
                        }
                    } else {
                        this.run_slot(ctx, idx, peer).await
                    };
                    (idx, slot)
                }
                .instrument(span),
            );
        }
        let mut slots: Vec<Option<SlotResult>> = (0..targets.len()).map(|_| None).collect();
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((idx, slot)) => slots[idx] = Some(slot),
                Err(e) => tracing::error!(error = %e, "replica task did not complete"),
            }
        }
        // A replica whose task panicked is a failed replica, not a reason to
        // abandon the others.
        let mut attempts = Vec::new();
        let replicas: Vec<ReplicaResult> = slots
            .into_iter()
            .zip(&targets)
            .map(|(slot, target)| match slot {
                Some(slot) => {
                    attempts.extend(slot.attempts);
                    slot.replica
                }
                None => ReplicaResult {
                    peer: target.peer_id,
                    remote: target.peer_id != self.local_peer_id,
                    outcome: Err(DispatchError::RemoteTransport {
                        peer: target.peer_id,
                        reason: "replica task did not complete (panicked or cancelled)".into(),
                    }),
                },
            })
            .collect();
        // The peers that ended up producing each replica (a slot may have
        // failed over to another worker).
        let final_peers: Vec<PeerId> = replicas.iter().map(|r| r.peer).collect();

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
        let executed_component = acceptance
            .reports
            .get(acceptance.chosen)
            .and_then(|r| r.component);
        let mut chosen = targets[acceptance.chosen].clone();
        if let Some(peer) = final_peers.get(acceptance.chosen) {
            if *peer != chosen.peer_id {
                chosen.reason = format!(
                    "{} — failed over from {} (see attempts)",
                    chosen.reason, chosen.peer_id
                );
                chosen.peer_id = *peer;
            }
        }
        Ok(DispatchResult {
            chosen,
            output: acceptance.output,
            policy_hash: envelope.hash(),
            replicas: acceptance.reports,
            pair_agreement: acceptance.pair_agreement,
            spot_check,
            attempts,
            executed_component,
        })
    }

    /// Run one remote replica — `first`, then retries and a backup copy as
    /// [`crate::retry`] allows — until an attempt yields a valid result or
    /// nothing more may be tried. See the module docs.
    async fn run_slot(&self, ctx: Arc<SlotCtx>, slot: usize, first: PeerId) -> SlotResult {
        let mut attempts: Vec<Attempt> = Vec::new();
        let mut tried: HashSet<PeerId> = HashSet::from([first]);
        let mut set: tokio::task::JoinSet<AttemptDone> = tokio::task::JoinSet::new();
        let mut running: HashMap<tokio::task::Id, Running> = HashMap::new();
        self.launch(
            &ctx,
            &mut set,
            &mut running,
            &mut attempts,
            slot,
            first,
            AttemptKind::First,
        );
        let mut retries: u32 = 0;
        let mut speculated = false;
        // Results that were not valid, in arrival order.
        let mut rejected: Vec<ReplicaResult> = Vec::new();
        loop {
            // A backup copy is started once, while exactly one attempt runs.
            let backup_at = match ctx.threshold {
                Some(t) if !speculated && running.len() == 1 => {
                    running.values().next().map(|r| r.started + t)
                }
                _ => None,
            };
            tokio::select! {
                joined = set.join_next_with_id(), if !set.is_empty() => {
                    let Some(joined) = joined else { continue };
                    let (id, done) = match joined {
                        Ok((id, done)) => (id, Some(done)),
                        Err(e) => (e.id(), None),
                    };
                    let Some(run) = running.remove(&id) else { continue };
                    let (replica, cause, took) = match done {
                        Some((replica, cause, took)) => (replica, cause, took),
                        None => (
                            ReplicaResult {
                                peer: run.peer,
                                remote: true,
                                outcome: Err(DispatchError::RemoteTransport {
                                    peer: run.peer,
                                    reason: "the attempt did not complete (panicked)".into(),
                                }),
                            },
                            None,
                            run.started.elapsed(),
                        ),
                    };
                    attempts[run.attempt].elapsed = took;
                    if is_valid(&replica, &ctx) {
                        // The first valid result wins; every other copy of
                        // this replica is cancelled.
                        attempts[run.attempt].outcome = AttemptOutcome::Used;
                        self.history.record(&ctx.task.plugin, took);
                        for (_, other) in running.drain() {
                            attempts[other.attempt].outcome = AttemptOutcome::Cancelled;
                            attempts[other.attempt].elapsed = other.started.elapsed();
                            self.cancel_remote(other.peer, other.task_id);
                            self.count_speculative("cancelled");
                        }
                        set.abort_all();
                        if speculated {
                            self.count_speculative(if run.kind == AttemptKind::Speculative {
                                "won"
                            } else {
                                "lost"
                            });
                        }
                        // Discarded results never reach acceptance: apply
                        // the penalties it would have.
                        for bad in &rejected {
                            self.penalize_discarded(&ctx, bad);
                        }
                        return SlotResult { replica, attempts };
                    }
                    attempts[run.attempt].outcome = AttemptOutcome::Failed(describe_failure(&replica));
                    let answered_invalid = replica.outcome.is_ok();
                    let failed_peer = replica.peer;
                    rejected.push(replica);
                    if !running.is_empty() {
                        // Another copy is still running: it may yet win.
                        continue;
                    }
                    let Some(cause) = cause.filter(|_| !answered_invalid) else { break };
                    if retries + 1 >= u32::from(ctx.task.retry.attempts()) {
                        break;
                    }
                    let now = Instant::now();
                    if now >= ctx.deadline {
                        break;
                    }
                    let Some(target) = self.claim_failover(&ctx, &tried, Some((cause, failed_peer))) else {
                        tracing::info!(
                            peer = %failed_peer,
                            cause = cause.label(),
                            plugin = %ctx.task.plugin,
                            "attempt failed and may be retried, but no eligible worker is left"
                        );
                        break;
                    };
                    retries += 1;
                    let wait = ctx.task.retry.backoff(retries).min(ctx.deadline - now);
                    tracing::info!(
                        failed = %failed_peer,
                        next = %target,
                        cause = cause.label(),
                        retry = retries,
                        wait_ms = wait.as_millis() as u64,
                        plugin = %ctx.task.plugin,
                        "retrying a failed attempt"
                    );
                    if let Some(reg) = &self.metrics {
                        catalog::scheduler_retry(reg, "one_shot", cause.label());
                    }
                    tokio::time::sleep(wait).await;
                    if Instant::now() >= ctx.deadline {
                        break;
                    }
                    tried.insert(target);
                    self.launch(
                        &ctx,
                        &mut set,
                        &mut running,
                        &mut attempts,
                        slot,
                        target,
                        AttemptKind::Retry(cause),
                    );
                }
                () = sleep_until_opt(backup_at) => {
                    speculated = true;
                    match self.claim_failover(&ctx, &tried, None) {
                        Some(target) => {
                            tracing::info!(
                                slow = ?running.values().next().map(|r| r.peer),
                                backup = %target,
                                plugin = %ctx.task.plugin,
                                "attempt is past the speculation threshold; starting a backup copy"
                            );
                            tried.insert(target);
                            self.count_speculative("launched");
                            self.launch(
                                &ctx,
                                &mut set,
                                &mut running,
                                &mut attempts,
                                slot,
                                target,
                                AttemptKind::Speculative,
                            );
                        }
                        None => tracing::debug!(
                            plugin = %ctx.task.plugin,
                            "attempt is past the speculation threshold, but no other eligible \
                             worker can take a backup copy"
                        ),
                    }
                }
            }
        }
        // Nothing valid: report the most telling result — an answer that
        // broke an integrity guard (acceptance penalises and reports it),
        // else the last failure — and penalise the other discarded answers.
        let pick = rejected
            .iter()
            .position(|r| discarded_penalty(r, &ctx).is_some())
            .unwrap_or(rejected.len().saturating_sub(1));
        let replica = if rejected.is_empty() {
            ReplicaResult {
                peer: first,
                remote: true,
                outcome: Err(DispatchError::RemoteTransport {
                    peer: first,
                    reason: "no attempt completed".into(),
                }),
            }
        } else {
            let replica = rejected.remove(pick);
            for bad in &rejected {
                self.penalize_discarded(&ctx, bad);
            }
            replica
        };
        SlotResult { replica, attempts }
    }

    /// Start one attempt of slot `slot` on `peer`.
    #[allow(clippy::too_many_arguments)]
    fn launch(
        &self,
        ctx: &Arc<SlotCtx>,
        set: &mut tokio::task::JoinSet<AttemptDone>,
        running: &mut HashMap<tokio::task::Id, Running>,
        attempts: &mut Vec<Attempt>,
        slot: usize,
        peer: PeerId,
        kind: AttemptKind,
    ) {
        let now = Instant::now();
        // A first attempt goes out as the task; a retry or a backup copy is
        // a new request — a fresh id (the executor refuses a second frame
        // with an id it is still running), the time left to the task's
        // deadline, and, like every request, a fresh per-attempt capability
        // token (minted when its link connects).
        let (task_id, timeout_ms) = match kind {
            AttemptKind::First => (ctx.task.id, ctx.task.timeout_ms),
            AttemptKind::Retry(_) | AttemptKind::Speculative => (
                uuid::Uuid::new_v4(),
                u64::try_from(ctx.deadline.saturating_duration_since(now).as_millis())
                    .unwrap_or(u64::MAX)
                    .max(1),
            ),
        };
        let attempt = attempts.len();
        attempts.push(Attempt {
            replica: slot,
            peer,
            remote: true,
            task_id,
            kind,
            outcome: AttemptOutcome::Failed("still running".into()),
            elapsed: Duration::ZERO,
        });
        let this = self.clone();
        let ctx = Arc::clone(ctx);
        // The attempt runs on its own task, inside the dispatch's span, so
        // its `remote.dispatch` span (and the worker's) stays in the
        // submitter's trace.
        let span = tracing::Span::current();
        let handle = set.spawn(
            async move {
                let started = Instant::now();
                let attempt_task;
                let task: &OneShotTask = if task_id == ctx.task.id {
                    &ctx.task
                } else {
                    attempt_task = OneShotTask {
                        id: task_id,
                        timeout_ms,
                        ..(*ctx.task).clone()
                    };
                    &attempt_task
                };
                let (replica, cause) = this.remote_attempt(task, peer, &ctx.envelope).await;
                (replica, cause, started.elapsed())
            }
            .instrument(span),
        );
        running.insert(
            handle.id(),
            Running {
                peer,
                task_id,
                kind,
                started: now,
                attempt,
            },
        );
    }

    /// A worker for a retry (`retry`: the cause and the worker that failed)
    /// or a backup copy (`None`), claimed as a replica holder: the
    /// best-ranked eligible live worker that holds no replica of the task
    /// and was not tried for this one; for a single-replica task lost after
    /// the request was sent, the same worker when there is no other.
    fn claim_failover(
        &self,
        ctx: &SlotCtx,
        tried: &HashSet<PeerId>,
        retry: Option<(RetryCause, PeerId)>,
    ) -> Option<PeerId> {
        let mut holders = ctx.holders.lock();
        let candidate = self
            .failover_candidates(&ctx.task)
            .into_iter()
            .find(|p| !tried.contains(p) && !holders.contains(p));
        if let Some(peer) = candidate {
            holders.insert(peer);
            return Some(peer);
        }
        match retry {
            Some((cause, last)) if !ctx.replicated && cause.may_return_to_same_worker() => {
                Some(last)
            }
            _ => None,
        }
    }

    /// Live remote workers eligible to run `task`, best-ranked first: they
    /// fit its resources, are on its `TrustedExecutor` allowlist when it
    /// has one, and their reputation for its policy is not `Excluded`.
    fn failover_candidates(&self, task: &OneShotTask) -> Vec<PeerId> {
        if self.remote.is_none() {
            return Vec::new();
        }
        let kind = task.integrity.kind();
        let mut live = self.workers.live(self.worker_ttl);
        if let IntegrityPolicy::TrustedExecutor { allowlist } = &task.integrity {
            live.retain(|w| allowlist.contains(&w.peer_id));
        }
        let Ok(ranked) = rank(&live, &task.resources) else {
            return Vec::new();
        };
        ranked
            .into_iter()
            .map(|c| c.peer_id)
            .filter(|p| *p != self.local_peer_id && self.verifier.reputation().is_eligible(p, kind))
            .collect()
    }

    /// Tell `peer` to stop running `task_id` (best effort, in the
    /// background).
    fn cancel_remote(&self, peer: PeerId, task_id: TaskId) {
        let Some(remote) = self.remote.clone() else {
            return;
        };
        tokio::spawn(async move {
            if let Err(e) = remote.send_cancel(peer, task_id, CANCEL_TIMEOUT).await {
                tracing::debug!(%peer, task = %task_id, error = %e, "cancel frame not acknowledged");
            }
        });
    }

    /// Apply the penalty acceptance would have applied to a result that was
    /// discarded because another copy of its replica won.
    fn penalize_discarded(&self, ctx: &SlotCtx, replica: &ReplicaResult) {
        if !replica.remote {
            return;
        }
        if let Some(reason) = discarded_penalty(replica, ctx) {
            if reason == ReputationReason::OversizedOutput {
                let actual = match &replica.outcome {
                    Ok(out) => out.bytes.len() as u64,
                    Err(DispatchError::OutputSizeExceeded(EntangleError::OutputSizeExceeded {
                        actual,
                        ..
                    })) => *actual,
                    Err(_) => 0,
                };
                OutputSizeExceededWarning {
                    peer_id: replica.peer,
                    declared: ctx.task.max_output_bytes,
                    actual,
                }
                .emit();
                if let Some(reg) = &self.metrics {
                    catalog::output_size_exceeded(reg);
                }
            }
            self.verifier
                .reputation()
                .penalize(&replica.peer, ctx.task.integrity.kind(), reason);
        }
    }

    fn count_speculative(&self, event: &str) {
        if let Some(reg) = &self.metrics {
            catalog::scheduler_speculative(reg, event);
        }
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
                    task_id: None,
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
        // The root of a trace of its own: a re-run frame carries the current
        // trace context, and must not tell its executor which dispatch (and
        // so which replicas) it checks. Linked here with `follows_from`, and
        // by the `task_id` attribute, which stays on this node.
        let span = tracing::info_span!(
            parent: None,
            "integrity.spot_check",
            task_id = %task.id,
            plugin = %task.plugin,
            policy = %kind,
            // Known once an executor has produced the re-run.
            checker = tracing::field::Empty,
            checker_remote = tracing::field::Empty,
        );
        span.follows_from(tracing::Span::current().id());
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
            rerun_task_id: None,
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
        record.rerun_task_id = out.task_id;
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
    ///
    /// The re-run is sent under a **fresh task id**: with the checked task's
    /// id a node linked to one of its replicas would know exactly which
    /// frame re-checks which accepted task.
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
        let task = &OneShotTask {
            id: uuid::Uuid::new_v4(),
            ..task.clone()
        };
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
            task_id: remote.then_some(task.id),
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
        let component = self.local_component(&task.plugin);
        let outcome = self
            .kernel
            .invoke(&task.plugin, &task.input, task.timeout_ms)
            .await
            .map(|bytes| ReplicaBytes {
                bytes,
                observed_policy_hash: envelope.recompute_hash(),
                component,
            })
            .map_err(DispatchError::from);
        ReplicaResult {
            peer: self.local_peer_id,
            remote: false,
            outcome,
        }
    }

    /// BLAKE3 of the artifact this node's kernel would run for `plugin`
    /// (the version answering for it after a hot reload).
    fn local_component(&self, plugin: &entangle_types::plugin_id::PluginId) -> Option<[u8; 32]> {
        let source = self.kernel.loaded_source(&self.kernel.resolve(plugin)?)?;
        let mut digest = [0u8; 32];
        hex::decode_to_slice(&source.artifact_digest, &mut digest).ok()?;
        Some(digest)
    }

    /// One replica on `peer`. Only called when a transport is configured.
    async fn remote_replica(
        &self,
        task: &OneShotTask,
        peer: PeerId,
        envelope: &PolicyEnvelope,
    ) -> ReplicaResult {
        self.remote_attempt(task, peer, envelope).await.0
    }

    /// One attempt on `peer`, with why its failure may be retried.
    async fn remote_attempt(
        &self,
        task: &OneShotTask,
        peer: PeerId,
        envelope: &PolicyEnvelope,
    ) -> (ReplicaResult, Option<RetryCause>) {
        let (outcome, cause) = match &self.remote {
            Some(remote) => {
                let attempt = remote.dispatch_attempt(task, peer, envelope).await;
                if let Some(reg) = &self.metrics {
                    catalog::remote_dispatch(
                        reg,
                        &remote_outcome(&attempt.result),
                        crate::transport::TransportKind::label(attempt.transport),
                    );
                }
                (
                    attempt.result.map(|r| ReplicaBytes {
                        bytes: r.output,
                        observed_policy_hash: r.observed_policy_hash,
                        component: r.component,
                    }),
                    attempt.cause,
                )
            }
            None => (
                Err(DispatchError::RemoteNotImplemented {
                    peer,
                    reason: "no mesh transport configured".into(),
                }),
                None,
            ),
        };
        (
            ReplicaResult {
                peer,
                remote: true,
                outcome,
            },
            cause,
        )
    }
}

/// What every slot of one task shares.
struct SlotCtx {
    task: Arc<OneShotTask>,
    envelope: Arc<PolicyEnvelope>,
    /// No retry starts after this: the first attempt plus `timeout_ms`.
    deadline: Instant,
    /// Whether the task has several replicas (a retry then never goes back
    /// to the worker it left).
    replicated: bool,
    /// Every worker holding (or that held) a replica of the task, across
    /// all its slots: no retry or backup copy goes to one.
    holders: Arc<parking_lot::Mutex<HashSet<PeerId>>>,
    /// When to start a backup copy of a slow attempt, if at all.
    threshold: Option<Duration>,
}

/// An attempt in flight.
struct Running {
    peer: PeerId,
    task_id: TaskId,
    kind: AttemptKind,
    started: Instant,
    /// Its index in the slot's attempts.
    attempt: usize,
}

/// What an attempt's task returns.
type AttemptDone = (ReplicaResult, Option<RetryCause>, Duration);

/// A slot's result: the replica to judge and every attempt made for it.
struct SlotResult {
    replica: ReplicaResult,
    attempts: Vec<Attempt>,
}

/// Whether `replica` passes the guards acceptance applies first: it has an
/// output, within `max_output_bytes`, and echoes the dispatched policy hash.
fn is_valid(replica: &ReplicaResult, ctx: &SlotCtx) -> bool {
    matches!(&replica.outcome, Ok(out)
        if out.bytes.len() as u64 <= ctx.task.max_output_bytes
            && out.observed_policy_hash == ctx.envelope.hash())
}

/// The penalty acceptance applies to `replica`, if any: an oversized output
/// or a policy-hash mismatch.
fn discarded_penalty(replica: &ReplicaResult, ctx: &SlotCtx) -> Option<ReputationReason> {
    match &replica.outcome {
        Ok(out) if out.bytes.len() as u64 > ctx.task.max_output_bytes => {
            Some(ReputationReason::OversizedOutput)
        }
        Ok(out) if out.observed_policy_hash != ctx.envelope.hash() => {
            Some(ReputationReason::PolicyHashMismatch)
        }
        Err(DispatchError::OutputSizeExceeded(_)) => Some(ReputationReason::OversizedOutput),
        _ => None,
    }
}

/// One line on why `replica` is not usable.
fn describe_failure(replica: &ReplicaResult) -> String {
    match &replica.outcome {
        Err(e) => e.to_string(),
        Ok(out) => format!(
            "answered with {} bytes that do not pass the output-size or policy-hash guard",
            out.bytes.len()
        ),
    }
}

/// The attempt record of a replica run on this node's kernel.
fn local_attempt(slot: usize, replica: &ReplicaResult, task_id: TaskId, took: Duration) -> Attempt {
    Attempt {
        replica: slot,
        peer: replica.peer,
        remote: false,
        task_id,
        kind: AttemptKind::First,
        outcome: match &replica.outcome {
            Ok(_) => AttemptOutcome::Used,
            Err(e) => AttemptOutcome::Failed(e.to_string()),
        },
        elapsed: took,
    }
}

/// Sleep until `at`, or forever without one.
async fn sleep_until_opt(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
        None => std::future::pending().await,
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
    /// The (fresh) id it was sent to `executor` under; `None` when it ran
    /// on this node.
    task_id: Option<TaskId>,
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
