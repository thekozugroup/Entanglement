//! Submitter-side integrity verification (spec §7.5).
//!
//! Everything here runs on the **submitter** — the node that dispatched the
//! task and will consume its output. Workers execute a task once per replica
//! and return raw bytes; they never evaluate a policy and never instantiate a
//! metric component (§7.5 Rule 3, verifier-locality).
//!
//! The [`IntegrityVerifier`] owns the three pieces of submitter state:
//!
//! * a [`MetricRegistry`] of verified `SemanticEquivalent` metric components;
//! * a [`ReputationStore`] (§7.5 Layer 3);
//! * the submitter's identity, for labelling.
//!
//! # Submit time — [`IntegrityVerifier::validate_submit`]
//!
//! Before placement, before anything is sent anywhere:
//!
//! * `Attested` is refused (`ENTANGLE-E0304`, TEE attestation is Phase 4+);
//! * replica counts, quorum and threshold must be usable (`E0313`);
//! * a `SemanticEquivalent` metric must be signed by a key on **this node's**
//!   keyring (`E0307 MetricNotInKeyring`, ATC-INT-2) and loaded here (`E0309`);
//! * the policy is sealed into a [`PolicyEnvelope`] (INV-INT-1).
//!
//! # Result time — [`IntegrityVerifier::accept`]
//!
//! The acceptance pipeline, in this order:
//!
//! 1. **Size guard (INV-INT-2).** Any replica whose actual output exceeds the
//!    task's `max_output_bytes` — whether the wire decoder already refused it
//!    or the bytes are in hand — emits an [`OutputSizeExceededWarning`] to
//!    telemetry, lowers that peer's reputation, and makes the task fail with
//!    `ENTANGLE-E0300 OutputSizeExceeded`. This branch is terminal and sits
//!    above the only metric load site, so an oversized result can never cause
//!    a metric instantiation; verifier memory stays bounded by
//!    `N × max_output_bytes`.
//! 2. **Policy-hash guard (INV-INT-1).** Every replica's echoed
//!    `observed_policy_hash` must equal the dispatched hash; otherwise the
//!    peer is penalised and the task fails with `E0315`.
//! 3. **Policy acceptance.**
//!    * `None` / `TrustedExecutor` / `Deterministic { 0 | 1 }` — the single
//!      replica's output.
//!    * `Deterministic { N }` — all `N` replicas must be present and
//!      byte-identical (BLAKE3). On a mismatch with a strict majority, the
//!      peers outside the majority are penalised.
//!    * `SemanticEquivalent` — see below.
//!
//! # `SemanticEquivalent` acceptance and the canonical output
//!
//! The successful replicas are put in **canonical order**: ascending BLAKE3 of
//! the output bytes, then peer id, then dispatch index — so the order depends
//! only on what came back, not on arrival timing. For every pair `(i, j)`,
//! `i < j` in that order, the submitter runs `metric.compare(out_i, out_j)`
//! once — exactly one component instantiation per pair (ATC-INT-1). A pair
//! *agrees* when its distance is `< threshold`.
//!
//! A comparison the metric cannot finish (trap, timeout, memory limit —
//! `E0311`; `NaN` or a negative distance — `E0312`) counts as incomparable
//! (`+inf`) for that pair and is logged as a `MetricComparisonFailed` event
//! at [`TELEMETRY_TARGET`]; evaluation continues. A replica *all* of whose
//! comparisons failed while other outputs compared fine is marked `failed`
//! (with the metric error) and penalised
//! ([`ReputationReason::IncomparableOutput`]) whatever the verdict. Only when
//! no comparison succeeds at all is the metric error itself returned.
//!
//! The candidate (canonical) output is the replica that
//!
//! 1. agrees with the most other replicas;
//! 2. on a tie, has the most agreeing pairs in its agreement cluster (itself
//!    plus every replica that agrees with it — see [`cluster_support`]);
//! 3. on a further tie, has the smallest sum of distances to the replicas it
//!    agrees with;
//! 4. on a further tie, comes first in canonical order (smallest output
//!    BLAKE3).
//!
//! The task is accepted iff the candidate's agreement cluster contains at
//! least `quorum` agreeing pairs. The spec's rule ("accept iff distance <
//! threshold for >= quorum pairs") is applied to the pairs that back the
//! returned output: agreeing pairs in an unrelated cluster — for instance
//! colluders returning identical bytes — never count toward another output's
//! quorum. The reported `pair_agreement` / `QuorumNotReached::agreeing` is
//! that cluster count.
//!
//! If another replica agrees with as many others as the candidate does but
//! not with the candidate itself, two equally large groups contradict each
//! other: the task is refused with `E0318 AmbiguousAgreement` and nobody is
//! blamed. Rules 2–4 above therefore only ever choose among replicas that
//! agree with one another, so neither closeness (which favours colluders
//! returning byte-identical output) nor BLAKE3 order (which can be ground)
//! decides between contradicting answers.
//!
//! The accepted cluster is the canonical replica plus every replica that
//! agrees with it: remote peers in the cluster are recorded as correct, remote
//! peers outside it are penalised for disagreeing with the accepted quorum.
//! When the quorum is not reached nothing is attributed (there is no accepted
//! answer to disagree with).
//!
//! Replicas run on the submitter's own kernel (the local fallback for
//! replicas that have no remote target) are verified identically but never
//! touch reputation.

use std::sync::Arc;

use entangle_runtime::{verify_deterministic, IntegrityError, MetricRegistry, ReplicaOutput};
use entangle_signing::Keyring;
use entangle_types::errors::EntangleError;
use entangle_types::peer_id::PeerId;
use entangle_types::task::{IntegrityPolicy, OneShotTask, PolicyKind};
use parking_lot::RwLock;

use crate::dispatcher::DispatchError;
use crate::reputation::{ReputationReason, ReputationStore};
use crate::work_unit::{PolicyEnvelope, PolicyHash};

/// Most replicas a single task may request (bounds both the fan-out and the
/// `N·(N-1)/2` metric instantiations of a `SemanticEquivalent` task).
pub const MAX_REPLICAS: u8 = 16;

/// `tracing` target for structured integrity telemetry events.
pub const TELEMETRY_TARGET: &str = "entangle::telemetry";

/// Structured telemetry event emitted every time the INV-INT-2 size guard
/// trips (spec §7.1 / §7.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputSizeExceededWarning {
    /// The peer whose replica was oversized.
    pub peer_id: PeerId,
    /// The task's `max_output_bytes`.
    pub declared: u64,
    /// The size the peer actually returned.
    pub actual: u64,
}

impl OutputSizeExceededWarning {
    /// The `event` field value carried by the tracing event.
    pub const EVENT: &'static str = "OutputSizeExceededWarning";

    /// Emit as a `WARN` event at [`TELEMETRY_TARGET`] with fields `event`,
    /// `peer_id`, `declared` and `actual`.
    pub fn emit(&self) {
        tracing::warn!(
            target: TELEMETRY_TARGET,
            event = Self::EVENT,
            peer_id = %self.peer_id,
            declared = self.declared,
            actual = self.actual,
            "replica output exceeds max_output_bytes; rejected before any metric was loaded"
        );
    }
}

/// The bytes one replica returned, with the policy hash it observed.
#[derive(Clone, Debug)]
pub struct ReplicaBytes {
    /// Raw output.
    pub bytes: Vec<u8>,
    /// The hash the executor echoed (for a local replica: the hash the
    /// submitter itself recomputed when the replica finished).
    pub observed_policy_hash: PolicyHash,
}

/// One replica's result as handed to [`IntegrityVerifier::accept`].
#[derive(Debug)]
pub struct ReplicaResult {
    /// Who executed it.
    pub peer: PeerId,
    /// `false` for a replica run on the submitter's own kernel.
    pub remote: bool,
    /// Output, or why there is none.
    pub outcome: Result<ReplicaBytes, DispatchError>,
}

/// What became of one replica, for audit and `--json` output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplicaStatus {
    /// Its output is the one returned.
    Canonical,
    /// It agreed with the returned output (identical bytes, or metric
    /// distance below the threshold).
    Agreed,
    /// It produced output that disagreed with the accepted answer.
    Disagreed,
    /// It produced no usable output.
    Failed(String),
}

impl ReplicaStatus {
    /// Stable lowercase label: `canonical`, `agreed`, `disagreed`, `failed`.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Canonical => "canonical",
            Self::Agreed => "agreed",
            Self::Disagreed => "disagreed",
            Self::Failed(_) => "failed",
        }
    }

    /// The failure reason, for [`ReplicaStatus::Failed`].
    pub fn error(&self) -> Option<&str> {
        match self {
            Self::Failed(reason) => Some(reason),
            _ => None,
        }
    }
}

/// Per-replica audit record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaReport {
    /// Who executed it.
    pub peer: PeerId,
    /// Whether it ran on another node.
    pub remote: bool,
    /// The policy hash it reported observing.
    pub observed_policy_hash: Option<PolicyHash>,
    /// Size of its output.
    pub output_bytes: Option<u64>,
    /// BLAKE3 of its output.
    pub output_blake3: Option<[u8; 32]>,
    /// What became of it.
    pub status: ReplicaStatus,
}

/// An accepted result.
#[derive(Clone, Debug)]
pub struct Acceptance {
    /// The canonical output.
    pub output: Vec<u8>,
    /// Index (in the `replicas` passed to `accept`) of the replica whose
    /// output was returned.
    pub chosen: usize,
    /// One report per replica, in the order they were passed in.
    pub reports: Vec<ReplicaReport>,
    /// For `SemanticEquivalent`: `(agreeing pairs backing the returned
    /// output, pairs compared)`.
    pub pair_agreement: Option<(usize, usize)>,
}

/// The submitter's integrity state: metrics, reputation, identity.
#[derive(Debug)]
pub struct IntegrityVerifier {
    metrics: Arc<MetricRegistry>,
    reputation: Arc<ReputationStore>,
    local_peer: PeerId,
}

impl IntegrityVerifier {
    /// A verifier for `local_peer` whose metric trust root is `keyring`
    /// (normally the kernel's keyring), with an empty metric registry and a
    /// fresh reputation store.
    pub fn new(keyring: Arc<RwLock<Keyring>>, local_peer: PeerId) -> Self {
        Self::with_parts(
            Arc::new(MetricRegistry::new(keyring, local_peer.to_hex())),
            Arc::new(ReputationStore::new()),
            local_peer,
        )
    }

    /// Assemble from existing parts (e.g. a reputation store shared with
    /// other components).
    pub fn with_parts(
        metrics: Arc<MetricRegistry>,
        reputation: Arc<ReputationStore>,
        local_peer: PeerId,
    ) -> Self {
        Self {
            metrics,
            reputation,
            local_peer,
        }
    }

    /// The verified metric components this node can run.
    pub fn metrics(&self) -> &Arc<MetricRegistry> {
        &self.metrics
    }

    /// Per-peer reputation.
    pub fn reputation(&self) -> &Arc<ReputationStore> {
        &self.reputation
    }

    /// The submitter's own peer id.
    pub fn local_peer(&self) -> PeerId {
        self.local_peer
    }

    /// Validate `policy` at submit time and seal it (see the module docs).
    pub fn validate_submit(
        &self,
        policy: &IntegrityPolicy,
    ) -> Result<PolicyEnvelope, IntegrityError> {
        match policy {
            IntegrityPolicy::Attested { .. } => {
                return Err(IntegrityError::NotImplemented("Attested"));
            }
            IntegrityPolicy::Deterministic { replicas } if *replicas > MAX_REPLICAS => {
                return Err(IntegrityError::InvalidPolicy(format!(
                    "Deterministic asks for {replicas} replicas; the maximum is {MAX_REPLICAS}"
                )));
            }
            IntegrityPolicy::SemanticEquivalent {
                replicas,
                quorum,
                metric,
                threshold,
            } => {
                if *replicas < 2 || *replicas > MAX_REPLICAS {
                    return Err(IntegrityError::InvalidPolicy(format!(
                        "SemanticEquivalent needs 2..={MAX_REPLICAS} replicas (at least one \
                         pair to compare), got {replicas}"
                    )));
                }
                let pairs = pair_count(*replicas as usize);
                if *quorum == 0 || *quorum as usize > pairs {
                    return Err(IntegrityError::InvalidPolicy(format!(
                        "quorum counts agreeing replica pairs: {replicas} replicas give {pairs} \
                         pairs, so quorum must be in 1..={pairs}, got {quorum}"
                    )));
                }
                if !threshold.is_finite() || *threshold <= 0.0 {
                    return Err(IntegrityError::InvalidPolicy(format!(
                        "threshold must be a finite distance > 0, got {threshold}"
                    )));
                }
                // §7.5 Rule 2 — the metric's publisher must be on *our*
                // keyring. ATC-INT-2: refused here, before placement.
                self.metrics.check_trusted(metric)?;
                if !self.metrics.contains(metric) {
                    return Err(IntegrityError::MetricUnavailable {
                        metric: metric.plugin.to_string(),
                        artifact: metric.artifact_hex(),
                    });
                }
            }
            _ => {}
        }
        PolicyEnvelope::seal(policy)
    }

    /// Run the acceptance pipeline over the collected replicas (see the
    /// module docs for the exact order and rules).
    ///
    /// `replicas` must be non-empty and in dispatch order. When the policy
    /// cannot be satisfied because replicas failed, the first failure (in
    /// dispatch order) is returned as-is, so a single unreachable peer reads
    /// as "unreachable", not as an integrity verdict.
    pub async fn accept(
        &self,
        task: &OneShotTask,
        envelope: &PolicyEnvelope,
        replicas: Vec<ReplicaResult>,
    ) -> Result<Acceptance, DispatchError> {
        let kind = envelope.policy().kind();
        let declared = task.max_output_bytes;

        // ── 1. INV-INT-2: size guard. Terminal, and above every metric load.
        let mut oversized: Option<DispatchError> = None;
        for r in &replicas {
            let actual = match &r.outcome {
                Ok(out) if out.bytes.len() as u64 > declared => Some(out.bytes.len() as u64),
                Err(DispatchError::OutputSizeExceeded(EntangleError::OutputSizeExceeded {
                    actual,
                    ..
                })) => Some(*actual),
                _ => None,
            };
            if let Some(actual) = actual {
                OutputSizeExceededWarning {
                    peer_id: r.peer,
                    declared,
                    actual,
                }
                .emit();
                if r.remote {
                    self.reputation
                        .penalize(&r.peer, kind, ReputationReason::OversizedOutput);
                }
                oversized.get_or_insert(DispatchError::OutputSizeExceeded(
                    EntangleError::OutputSizeExceeded {
                        declared,
                        actual,
                        peer: r.peer.to_hex(),
                    },
                ));
            }
        }
        if let Some(err) = oversized {
            return Err(err);
        }

        // ── 2. INV-INT-1: every replica observed the dispatched policy hash.
        let expected = envelope.hash();
        let mut mismatch: Option<IntegrityError> = None;
        for r in &replicas {
            if let Ok(out) = &r.outcome {
                if out.observed_policy_hash != expected {
                    if r.remote {
                        self.reputation.penalize(
                            &r.peer,
                            kind,
                            ReputationReason::PolicyHashMismatch,
                        );
                    }
                    mismatch.get_or_insert(IntegrityError::PolicyHashMismatch {
                        peer: r.peer.to_hex(),
                        expected: expected.to_hex(),
                        observed: out.observed_policy_hash.to_hex(),
                    });
                }
            }
        }
        if let Some(err) = mismatch {
            return Err(err.into());
        }

        // ── 3. Policy-specific acceptance.
        let mut reports: Vec<ReplicaReport> = replicas.iter().map(report_for).collect();
        let ok: Vec<usize> = (0..replicas.len())
            .filter(|&i| replicas[i].outcome.is_ok())
            .collect();

        match envelope.policy() {
            IntegrityPolicy::SemanticEquivalent {
                replicas: required,
                quorum,
                metric,
                threshold,
            } => {
                // Too few answers for `quorum` agreeing pairs to exist at all:
                // the cause is the replicas that failed, so report that (an
                // unreachable peer reads as "unreachable"), and run no metric.
                if ok.len() < 2 || pair_count(ok.len()) < *quorum as usize {
                    return Err(first_failure(replicas).unwrap_or(
                        IntegrityError::InsufficientReplicas {
                            actual: ok.len(),
                            required: *required,
                        }
                        .into(),
                    ));
                }
                let outputs: Vec<&[u8]> = replicas
                    .iter()
                    .map(|r| r.outcome.as_ref().map_or(&[][..], |o| o.bytes.as_slice()))
                    .collect();

                // Canonical order: output BLAKE3, then peer id, then index.
                let mut order = ok.clone();
                order.sort_by(|&a, &b| {
                    (reports[a].output_blake3, replicas[a].peer, a).cmp(&(
                        reports[b].output_blake3,
                        replicas[b].peer,
                        b,
                    ))
                });

                // One metric instantiation per pair — the only metric load
                // site, reachable only past guards 1 and 2.
                //
                // A comparison the metric cannot finish (trap, timeout, memory
                // limit: E0311; NaN or negative: E0312) makes that pair
                // incomparable (+inf, which the metric contract already
                // defines as "incomparable") instead of aborting the task: one
                // replica whose output breaks the metric must not be able to
                // veto an answer the others agree on.
                let n = order.len();
                let mut dist = vec![vec![f64::INFINITY; n]; n];
                let mut pairs = 0usize;
                let mut compared = vec![0usize; n];
                let mut pair_error: Vec<Option<IntegrityError>> = vec![None; n];
                let mut first_error: Option<IntegrityError> = None;
                for a in 0..n {
                    for b in (a + 1)..n {
                        pairs += 1;
                        let d = match self
                            .metrics
                            .compare(metric, outputs[order[a]], outputs[order[b]])
                            .await
                        {
                            Ok(d) => {
                                compared[a] += 1;
                                compared[b] += 1;
                                d
                            }
                            Err(
                                e @ (IntegrityError::MetricFailed { .. }
                                | IntegrityError::MetricContractViolation { .. }),
                            ) => {
                                tracing::warn!(
                                    target: TELEMETRY_TARGET,
                                    event = "MetricComparisonFailed",
                                    peer_a = %replicas[order[a]].peer,
                                    peer_b = %replicas[order[b]].peer,
                                    error = %e,
                                    "metric could not compare two replica outputs; \
                                     the pair counts as incomparable"
                                );
                                for p in [a, b] {
                                    if pair_error[p].is_none() {
                                        pair_error[p] = Some(e.clone());
                                    }
                                }
                                first_error.get_or_insert(e);
                                f64::INFINITY
                            }
                            // Trust or availability of the metric itself:
                            // nothing any replica did, so stop here.
                            Err(other) => return Err(other.into()),
                        };
                        dist[a][b] = d;
                        dist[b][a] = d;
                    }
                }
                // Not a single comparison succeeded: the metric (or every
                // output) is the problem, and no replica can be singled out.
                if compared.iter().all(|&c| c == 0) {
                    if let Some(e) = first_error {
                        return Err(e.into());
                    }
                }
                // A replica every one of whose comparisons failed, while
                // other outputs compared fine, is the one whose output broke
                // the metric: its audit carries the metric error and it loses
                // standing whatever the verdict.
                let incomparable: Vec<bool> = compared.iter().map(|&c| c == 0).collect();
                for (pos, &idx) in order.iter().enumerate() {
                    if !incomparable[pos] {
                        continue;
                    }
                    if let Some(e) = &pair_error[pos] {
                        reports[idx].status = ReplicaStatus::Failed(e.to_string());
                    }
                    if replicas[idx].remote {
                        self.reputation.penalize(
                            &replicas[idx].peer,
                            kind,
                            ReputationReason::IncomparableOutput,
                        );
                    }
                }
                // The quorum is counted among the pairs that back the output
                // we would return — its agreement cluster — so agreeing pairs
                // elsewhere (an unrelated cluster, possibly colluders) can
                // never lend their votes to it.
                let canonical_pos = choose_canonical(&dist, *threshold);
                let agreeing = cluster_support(&dist, *threshold, canonical_pos);
                if agreeing < *quorum as usize {
                    return Err(IntegrityError::QuorumNotReached {
                        agreeing,
                        pairs,
                        required: *quorum,
                    }
                    .into());
                }
                // Another replica agrees with as many others as the candidate
                // does but not with the candidate itself: two equally large
                // groups contradict each other. Any tie-break between them
                // (closeness favours colluders returning identical bytes;
                // BLAKE3 order can be ground) would be a guess, so refuse and
                // blame nobody.
                if let Some((candidates, agreements)) =
                    ambiguous_top(&dist, *threshold, canonical_pos)
                {
                    return Err(IntegrityError::AmbiguousAgreement {
                        candidates,
                        agreements,
                    }
                    .into());
                }

                let chosen = order[canonical_pos];
                for (pos, &idx) in order.iter().enumerate() {
                    if incomparable[pos] {
                        continue; // already recorded and penalised above
                    }
                    let agrees = pos == canonical_pos || dist[canonical_pos][pos] < *threshold;
                    reports[idx].status = if pos == canonical_pos {
                        ReplicaStatus::Canonical
                    } else if agrees {
                        ReplicaStatus::Agreed
                    } else {
                        ReplicaStatus::Disagreed
                    };
                    if replicas[idx].remote {
                        if agrees {
                            self.reputation.record_correct(&replicas[idx].peer, kind);
                        } else {
                            self.reputation.penalize(
                                &replicas[idx].peer,
                                kind,
                                ReputationReason::DisagreedWithQuorum,
                            );
                        }
                    }
                }
                let output = take_output(replicas, chosen);
                Ok(Acceptance {
                    output,
                    chosen,
                    reports,
                    pair_agreement: Some((agreeing, pairs)),
                })
            }
            IntegrityPolicy::Deterministic { replicas: n } if *n >= 2 => {
                let required = *n as usize;
                if ok.len() < required {
                    return Err(first_failure(replicas).unwrap_or(
                        IntegrityError::InsufficientReplicas {
                            actual: ok.len(),
                            required: *n,
                        }
                        .into(),
                    ));
                }
                let outs: Vec<ReplicaOutput> = ok
                    .iter()
                    .map(|&i| ReplicaOutput {
                        bytes: Vec::new(),
                        blake3: reports[i].output_blake3.unwrap_or_default(),
                    })
                    .collect();
                if let Err(e) = verify_deterministic(&outs, *n) {
                    self.penalize_hash_minority(&replicas, &ok, &reports, kind);
                    return Err(e.into());
                }
                for (pos, &i) in ok.iter().enumerate() {
                    reports[i].status = if pos == 0 {
                        ReplicaStatus::Canonical
                    } else {
                        ReplicaStatus::Agreed
                    };
                    if replicas[i].remote {
                        self.reputation.record_correct(&replicas[i].peer, kind);
                    }
                }
                let chosen = ok[0];
                Ok(Acceptance {
                    output: take_output(replicas, chosen),
                    chosen,
                    reports,
                    pair_agreement: None,
                })
            }
            // None, TrustedExecutor, Deterministic { 0 | 1 }: one replica.
            _ => {
                let Some(&chosen) = ok.first() else {
                    return Err(first_failure(replicas).unwrap_or(
                        IntegrityError::InsufficientReplicas {
                            actual: 0,
                            required: 1,
                        }
                        .into(),
                    ));
                };
                reports[chosen].status = ReplicaStatus::Canonical;
                Ok(Acceptance {
                    output: take_output(replicas, chosen),
                    chosen,
                    reports,
                    pair_agreement: None,
                })
            }
        }
    }

    /// On a `Deterministic` mismatch, penalise the remote peers outside a
    /// strict-majority hash group, if one exists.
    fn penalize_hash_minority(
        &self,
        replicas: &[ReplicaResult],
        ok: &[usize],
        reports: &[ReplicaReport],
        kind: PolicyKind,
    ) {
        let mut groups: std::collections::BTreeMap<[u8; 32], usize> = Default::default();
        for &i in ok {
            *groups
                .entry(reports[i].output_blake3.unwrap_or_default())
                .or_default() += 1;
        }
        let Some((majority, count)) = groups.iter().max_by_key(|(_, c)| **c) else {
            return;
        };
        if *count * 2 <= ok.len() {
            return; // no strict majority: nothing to attribute
        }
        for &i in ok {
            if replicas[i].remote && reports[i].output_blake3.as_ref() != Some(majority) {
                self.reputation.penalize(
                    &replicas[i].peer,
                    kind,
                    ReputationReason::DisagreedWithQuorum,
                );
            }
        }
    }
}

/// How many replicas `policy` asks for (at least 1).
pub fn replica_count(policy: &IntegrityPolicy) -> usize {
    match policy {
        IntegrityPolicy::Deterministic { replicas }
        | IntegrityPolicy::SemanticEquivalent { replicas, .. } => (*replicas).max(1) as usize,
        _ => 1,
    }
}

/// `n·(n-1)/2`.
pub fn pair_count(n: usize) -> usize {
    n.saturating_mul(n.saturating_sub(1)) / 2
}

/// Pick the canonical position from a symmetric distance matrix (positions
/// are in canonical order): most agreements, then the most agreeing pairs in
/// its agreement cluster ([`cluster_support`]), then smallest sum of agreeing
/// distances, then lowest position.
pub fn choose_canonical(dist: &[Vec<f64>], threshold: f64) -> usize {
    let mut best = 0usize;
    let mut best_key: Option<(usize, usize, f64)> = None;
    for (i, row) in dist.iter().enumerate() {
        let agreeing: Vec<f64> = row
            .iter()
            .enumerate()
            .filter(|&(j, d)| j != i && *d < threshold)
            .map(|(_, d)| *d)
            .collect();
        let degree = agreeing.len();
        let support = cluster_support(dist, threshold, i);
        let sum: f64 = agreeing.iter().sum();
        let better = match best_key {
            None => true,
            Some((bd, bp, bs)) => {
                degree > bd
                    || (degree == bd && support > bp)
                    || (degree == bd && support == bp && sum < bs)
            }
        };
        if better {
            best = i;
            best_key = Some((degree, support, sum));
        }
    }
    best
}

/// Whether the choice of position `c` is ambiguous: some other position
/// agrees with exactly as many others as `c` does, yet does not agree with
/// `c`. Returns `(candidates sharing c's agreement count, that count)` when
/// it is.
pub fn ambiguous_top(dist: &[Vec<f64>], threshold: f64, c: usize) -> Option<(usize, usize)> {
    let degree = |i: usize| {
        dist[i]
            .iter()
            .enumerate()
            .filter(|&(j, d)| j != i && *d < threshold)
            .count()
    };
    let top = degree(c);
    let tied: Vec<usize> = (0..dist.len()).filter(|&t| degree(t) == top).collect();
    let contradicted = tied.iter().any(|&t| t != c && dist[c][t] >= threshold);
    contradicted.then_some((tied.len(), top))
}

/// The number of agreeing pairs (`distance < threshold`) among position `c`
/// and the positions that agree with it — the pairs that back `c`'s output.
pub fn cluster_support(dist: &[Vec<f64>], threshold: f64, c: usize) -> usize {
    let Some(row) = dist.get(c) else {
        return 0;
    };
    let members: Vec<usize> = (0..row.len())
        .filter(|&j| j == c || row[j] < threshold)
        .collect();
    let mut support = 0;
    for (k, &i) in members.iter().enumerate() {
        for &j in &members[k + 1..] {
            if dist[i][j] < threshold {
                support += 1;
            }
        }
    }
    support
}

fn report_for(r: &ReplicaResult) -> ReplicaReport {
    match &r.outcome {
        Ok(out) => ReplicaReport {
            peer: r.peer,
            remote: r.remote,
            observed_policy_hash: Some(out.observed_policy_hash),
            output_bytes: Some(out.bytes.len() as u64),
            output_blake3: Some(*blake3::hash(&out.bytes).as_bytes()),
            status: ReplicaStatus::Disagreed,
        },
        Err(e) => ReplicaReport {
            peer: r.peer,
            remote: r.remote,
            observed_policy_hash: None,
            output_bytes: None,
            output_blake3: None,
            status: ReplicaStatus::Failed(e.to_string()),
        },
    }
}

fn first_failure(replicas: Vec<ReplicaResult>) -> Option<DispatchError> {
    replicas.into_iter().find_map(|r| r.outcome.err())
}

fn take_output(mut replicas: Vec<ReplicaResult>, chosen: usize) -> Vec<u8> {
    match replicas.swap_remove(chosen).outcome {
        Ok(out) => out.bytes,
        // `chosen` is always an index of a successful replica.
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reputation::INITIAL_SCORE;
    use crate::work_unit::policy_hash;
    use entangle_signing::IdentityKeyPair;
    use entangle_types::task::MetricRef;

    fn peer(b: u8) -> PeerId {
        PeerId::from_public_key_bytes(&[b; 32])
    }

    fn verifier() -> IntegrityVerifier {
        IntegrityVerifier::new(Arc::new(RwLock::new(Keyring::new())), peer(0))
    }

    fn task(policy: IntegrityPolicy, max_out: u64) -> OneShotTask {
        let mut t = OneShotTask::with_defaults(
            "0123456789abcdef0123456789abcdef/demo@1.0.0"
                .parse()
                .unwrap(),
            b"in".to_vec(),
        );
        t.integrity = policy;
        t.max_output_bytes = max_out;
        t
    }

    fn ok(p: u8, bytes: &[u8], h: PolicyHash) -> ReplicaResult {
        ReplicaResult {
            peer: peer(p),
            remote: true,
            outcome: Ok(ReplicaBytes {
                bytes: bytes.to_vec(),
                observed_policy_hash: h,
            }),
        }
    }

    fn unreachable(p: u8) -> ReplicaResult {
        ReplicaResult {
            peer: peer(p),
            remote: true,
            outcome: Err(DispatchError::RemoteTransport {
                peer: peer(p),
                reason: "unreachable".into(),
            }),
        }
    }

    /// A hand-written `entangle:integrity/metric@0.1.0` component whose
    /// distance is `|a[0] - b[0]| / 10` — so a test picks any distance matrix
    /// by choosing first bytes. An output starting with `0xFF` makes the guest
    /// trap (`MetricFailed`); one starting with `0xFE` makes it return `NaN`
    /// (`MetricContractViolation`). Outputs must be non-empty.
    fn first_byte_metric() -> Vec<u8> {
        wat::parse_str(
            r#"(component
  (core module $m
    (memory (export "memory") 1)
    (global $bump (mut i32) (i32.const 1024))
    (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
      (local $p i32) (local $end i32)
      (local.set $p
        (i32.and
          (i32.add (global.get $bump) (i32.sub (local.get 2) (i32.const 1)))
          (i32.sub (i32.const 0) (local.get 2))))
      (local.set $end (i32.add (local.get $p) (local.get 3)))
      (if (i32.gt_u (local.get $end) (i32.mul (memory.size) (i32.const 65536)))
        (then
          (if (i32.lt_s
                (memory.grow
                  (i32.add
                    (i32.div_u
                      (i32.sub (local.get $end) (i32.mul (memory.size) (i32.const 65536)))
                      (i32.const 65536))
                    (i32.const 1)))
                (i32.const 0))
            (then unreachable))))
      (global.set $bump (local.get $end))
      (local.get $p))
    (func (export "compare") (param $pa i32) (param $la i32) (param $pb i32) (param $lb i32) (result f64)
      (local $x i32) (local $y i32)
      (local.set $x (i32.load8_u (local.get $pa)))
      (local.set $y (i32.load8_u (local.get $pb)))
      (if (i32.or (i32.eq (local.get $x) (i32.const 255)) (i32.eq (local.get $y) (i32.const 255)))
        (then unreachable))
      (if (i32.or (i32.eq (local.get $x) (i32.const 254)) (i32.eq (local.get $y) (i32.const 254)))
        (then (return (f64.const nan))))
      (f64.div
        (f64.abs (f64.sub (f64.convert_i32_u (local.get $x)) (f64.convert_i32_u (local.get $y))))
        (f64.const 10))))
  (core instance $i (instantiate $m))
  (func $compare (param "a" (list u8)) (param "b" (list u8)) (result f64)
    (canon lift (core func $i "compare") (memory $i "memory") (realloc (func $i "cabi_realloc"))))
  (instance $metric (export "compare" (func $compare)))
  (export "entangle:integrity/metric@0.1.0" (instance $metric)))"#,
        )
        .expect("metric WAT must assemble")
    }

    /// A verifier whose keyring trusts one publisher, with
    /// [`first_byte_metric`] signed by it and loaded.
    fn verifier_with_metric() -> (IntegrityVerifier, MetricRef) {
        let kp = IdentityKeyPair::generate();
        let mut kr = Keyring::new();
        kr.add(entangle_signing::TrustEntry {
            fingerprint: kp.fingerprint(),
            public_key: *kp.public().as_bytes(),
            publisher_name: "metric-publisher".into(),
            added_at: 0,
            note: String::new(),
        });
        let v = IntegrityVerifier::new(Arc::new(RwLock::new(kr)), peer(0));
        let wasm = first_byte_metric();
        let manifest = format!(
            "[plugin]\nid = \"{}/first-byte@0.1.0\"\nversion = \"0.1.0\"\ntier = 2\n\
             runtime = \"wasm\"\n",
            kp.fingerprint_hex()
        );
        let bundle = entangle_signing::sign_artifact(&wasm, manifest.as_bytes(), &kp);
        let metric = v
            .metrics()
            .load_package("first-byte", &wasm, manifest.as_bytes(), &bundle)
            .expect("a signed metric loads");
        (v, metric)
    }

    fn sem_policy(metric: &MetricRef, replicas: u8, quorum: u8, threshold: f64) -> IntegrityPolicy {
        IntegrityPolicy::SemanticEquivalent {
            replicas,
            quorum,
            metric: metric.clone(),
            threshold,
        }
    }

    /// When the replicas that failed make the quorum impossible to reach, the
    /// first failure is reported as itself (here: an unreachable peer), not
    /// as an integrity verdict against the replicas that did answer — and no
    /// metric runs.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unreachable_quorum_reports_the_failure_not_a_verdict() {
        let (v, metric) = verifier_with_metric();
        let policy = sem_policy(&metric, 3, 3, 0.25);
        let env = PolicyEnvelope::seal(&policy).unwrap();
        let h = env.hash();
        // Two answers that agree (1 pair), one unreachable peer: 1 < quorum 3
        // whatever the metric says.
        let reps = vec![ok(1, &[10], h), ok(2, &[10], h), unreachable(3)];
        let err = v.accept(&task(policy, 1024), &env, reps).await.unwrap_err();
        assert!(
            matches!(err, DispatchError::RemoteTransport { .. }),
            "{err:?}"
        );
        assert_eq!(v.metrics().instantiations(&metric), 0);
    }

    fn report_of(acc: &Acceptance, p: u8) -> &ReplicaReport {
        acc.reports
            .iter()
            .find(|r| r.peer == peer(p))
            .expect("every replica is reported")
    }

    /// A replica whose output makes the metric fail — a trap (E0311) or a
    /// `NaN` (E0312) — cannot veto a task the other replicas agree on: its
    /// pairs count as incomparable, the honest pair still reaches quorum, the
    /// failure is recorded in its audit record, and it loses reputation.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_replica_that_breaks_the_metric_is_outvoted_and_penalised() {
        for (poison, code) in [(0xFF_u8, "ENTANGLE-E0311"), (0xFE, "ENTANGLE-E0312")] {
            let (v, metric) = verifier_with_metric();
            let policy = sem_policy(&metric, 3, 1, 0.25);
            let env = PolicyEnvelope::seal(&policy).unwrap();
            let h = env.hash();
            let reps = vec![ok(1, &[10], h), ok(2, &[11], h), ok(3, &[poison], h)];
            let acc = v
                .accept(&task(policy, 1024), &env, reps)
                .await
                .expect("the honest pair reaches quorum 1");
            assert!(acc.output == [10] || acc.output == [11], "{:?}", acc.output);
            assert_eq!(acc.pair_agreement, Some((1, 3)));
            assert_eq!(v.metrics().instantiations(&metric), 3, "every pair ran");
            let bad = report_of(&acc, 3);
            assert_eq!(bad.status.label(), "failed");
            assert!(
                bad.status.error().is_some_and(|e| e.contains(code)),
                "{:?}",
                bad.status
            );
            let k = PolicyKind::SemanticEquivalent;
            assert!(v.reputation().get(&peer(3), k) < INITIAL_SCORE);
            for p in [1, 2] {
                assert_eq!(v.reputation().record(&peer(p), k).correct, 1);
                assert_eq!(v.reputation().get(&peer(p), k), INITIAL_SCORE);
            }
        }
    }

    /// The replica every one of whose comparisons failed is penalised even
    /// when the others do not reach quorum; the others are not.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_incomparable_replica_is_penalised_even_without_quorum() {
        let (v, metric) = verifier_with_metric();
        let policy = sem_policy(&metric, 3, 1, 0.25);
        let env = PolicyEnvelope::seal(&policy).unwrap();
        let h = env.hash();
        // 10 vs 20: distance 1.0 — compared fine, but no agreement.
        let reps = vec![ok(1, &[10], h), ok(2, &[20], h), ok(3, &[0xFF], h)];
        let err = v.accept(&task(policy, 1024), &env, reps).await.unwrap_err();
        assert!(
            matches!(
                err,
                DispatchError::Integrity(IntegrityError::QuorumNotReached {
                    agreeing: 0,
                    pairs: 3,
                    required: 1
                })
            ),
            "{err:?}"
        );
        let k = PolicyKind::SemanticEquivalent;
        assert!(v.reputation().get(&peer(3), k) < INITIAL_SCORE);
        assert_eq!(v.reputation().record(&peer(1), k).total, 0);
        assert_eq!(v.reputation().record(&peer(2), k).total, 0);
    }

    /// Quorum is counted among the pairs that back the *returned* output (its
    /// agreement cluster), not across unrelated clusters. Here A agrees with
    /// B and C (B and C do not agree), and an unrelated pair D–E agrees:
    /// 3 agreeing pairs overall, but only 2 behind A — quorum 3 is not met.
    #[tokio::test(flavor = "multi_thread")]
    async fn quorum_counts_only_pairs_that_back_the_returned_output() {
        let (v, metric) = verifier_with_metric();
        let policy = sem_policy(&metric, 5, 3, 0.25);
        let env = PolicyEnvelope::seal(&policy).unwrap();
        let h = env.hash();
        // d(A,B) = d(A,C) = 0.2, d(B,C) = 0.4, d(D,E) = 0, D/E far from A–C.
        let reps = vec![
            ok(1, &[20], h),
            ok(2, &[18], h),
            ok(3, &[22], h),
            ok(4, &[60], h),
            ok(5, &[60], h),
        ];
        let err = v.accept(&task(policy, 1024), &env, reps).await.unwrap_err();
        assert!(
            matches!(
                err,
                DispatchError::Integrity(IntegrityError::QuorumNotReached {
                    agreeing: 2,
                    pairs: 10,
                    required: 3
                })
            ),
            "{err:?}"
        );
        // Nothing was accepted, so nobody is credited.
        let k = PolicyKind::SemanticEquivalent;
        for p in 1..=5 {
            assert_eq!(v.reputation().record(&peer(p), k).correct, 0, "peer {p}");
        }
    }

    /// The finding's scenario: honest H1–H2 agree (0.2), honest H3 is a
    /// paraphrase too far from both, and two colluders return byte-identical
    /// poison (distance 0). Two agreeing pairs meet quorum 2 overall, but the
    /// colluders' output is backed by one pair only: it must not be returned,
    /// and no honest peer may lose standing over it.
    #[tokio::test(flavor = "multi_thread")]
    async fn colluders_with_identical_bytes_cannot_borrow_an_honest_pair_for_quorum() {
        let (v, metric) = verifier_with_metric();
        let policy = sem_policy(&metric, 5, 2, 0.25);
        let env = PolicyEnvelope::seal(&policy).unwrap();
        let h = env.hash();
        let reps = vec![
            ok(1, &[10], h),
            ok(2, &[12], h),
            ok(3, &[15], h),
            ok(4, &[50], h),
            ok(5, &[50], h),
        ];
        let err = v.accept(&task(policy, 1024), &env, reps).await.unwrap_err();
        assert!(
            matches!(
                err,
                DispatchError::Integrity(IntegrityError::QuorumNotReached {
                    agreeing: 1,
                    pairs: 10,
                    required: 2
                })
            ),
            "{err:?}"
        );
        let k = PolicyKind::SemanticEquivalent;
        for p in 1..=3 {
            assert_eq!(v.reputation().get(&peer(p), k), INITIAL_SCORE, "peer {p}");
        }
        for p in 4..=5 {
            assert_eq!(v.reputation().record(&peer(p), k).correct, 0, "peer {p}");
        }
    }

    /// Two groups that agree internally but not with each other, each as well
    /// supported as the other: an honest pair (distance 0.1) and two
    /// colluders returning identical bytes (distance 0). Each group alone
    /// meets quorum 1, and the colluders would win any closeness tie-break.
    /// The verifier refuses the ambiguity instead of picking a side, and
    /// blames nobody.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_tie_between_disagreeing_groups_is_refused_without_blame() {
        let (v, metric) = verifier_with_metric();
        let policy = sem_policy(&metric, 4, 1, 0.25);
        let env = PolicyEnvelope::seal(&policy).unwrap();
        let h = env.hash();
        let reps = vec![
            ok(1, &[10], h),
            ok(2, &[11], h),
            ok(3, &[50], h),
            ok(4, &[50], h),
        ];
        let err = v.accept(&task(policy, 1024), &env, reps).await.unwrap_err();
        assert!(
            matches!(
                err,
                DispatchError::Integrity(IntegrityError::AmbiguousAgreement {
                    candidates: 4,
                    agreements: 1
                })
            ),
            "{err:?}"
        );
        assert!(err.to_string().contains("ENTANGLE-E0318"), "{err}");
        let k = PolicyKind::SemanticEquivalent;
        for p in 1..=4 {
            assert_eq!(v.reputation().record(&peer(p), k).total, 0, "peer {p}");
        }

        // A tie among replicas that all agree with one another is not
        // ambiguous: the closest one is returned.
        let (v, metric) = verifier_with_metric();
        let policy = sem_policy(&metric, 3, 1, 0.25);
        let env = PolicyEnvelope::seal(&policy).unwrap();
        let h = env.hash();
        let reps = vec![ok(1, &[10], h), ok(2, &[11], h), ok(3, &[12], h)];
        let acc = v.accept(&task(policy, 1024), &env, reps).await.unwrap();
        assert_eq!(acc.output, [11], "the middle output is closest to both");
        assert_eq!(acc.pair_agreement, Some((3, 3)));
    }

    /// When no comparison succeeds at all, the metric itself (or every
    /// output) is the problem: its error is reported and nobody is blamed.
    #[tokio::test(flavor = "multi_thread")]
    async fn when_every_comparison_fails_the_metric_error_is_reported() {
        let (v, metric) = verifier_with_metric();
        let policy = sem_policy(&metric, 2, 1, 0.25);
        let env = PolicyEnvelope::seal(&policy).unwrap();
        let h = env.hash();
        let err = v
            .accept(
                &task(policy, 1024),
                &env,
                vec![ok(1, &[10], h), ok(2, &[0xFF], h)],
            )
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                DispatchError::Integrity(IntegrityError::MetricFailed { .. })
            ),
            "{err:?}"
        );
        let k = PolicyKind::SemanticEquivalent;
        assert_eq!(v.reputation().record(&peer(1), k).total, 0);
        assert_eq!(v.reputation().record(&peer(2), k).total, 0);
    }

    #[test]
    fn canonical_choice_prefers_degree_then_support_then_closeness_then_position() {
        let inf = f64::INFINITY;
        // 0 agrees with 1; 2 agrees with 0 and 1 → 2 has the highest degree.
        let d = vec![
            vec![0.0, 0.1, 0.2],
            vec![0.1, 0.0, 0.2],
            vec![0.2, 0.2, 0.0],
        ];
        // Everyone agrees with everyone (degree 2 each); sums: 0.3, 0.3, 0.4.
        // Tie between 0 and 1 on degree and sum → lowest position wins.
        assert_eq!(choose_canonical(&d, 0.5), 0);
        // Threshold 0.15: only the 0–1 pair agrees → 0 and 1 have degree 1,
        // equal sums → position 0.
        assert_eq!(choose_canonical(&d, 0.15), 0);
        // 2 is the hub.
        let hub = vec![
            vec![0.0, inf, 0.1],
            vec![inf, 0.0, 0.1],
            vec![0.1, 0.1, 0.0],
        ];
        assert_eq!(choose_canonical(&hub, 0.5), 2);
        // Equal degree, smaller agreeing sum wins.
        let closer = vec![
            vec![0.0, 0.3, inf],
            vec![0.3, 0.0, 0.1],
            vec![inf, 0.1, 0.0],
        ];
        // degrees: 0→1 (0.3), 1→2 (0.4), 2→1 (0.1) → position 1 has degree 2.
        assert_eq!(choose_canonical(&closer, 0.5), 1);
        let pairish = vec![
            vec![0.0, 0.3, inf],
            vec![0.3, 0.0, inf],
            vec![inf, inf, 0.0],
        ];
        assert_eq!(choose_canonical(&pairish, 0.5), 0);
        assert_eq!(cluster_support(&pairish, 0.5, 0), 1);
        assert_eq!(cluster_support(&pairish, 0.5, 2), 0);

        // Equal degree (2): position 0 is a hub over two outputs that do not
        // agree with each other (support 2, sum 0.2); positions 3–5 form a
        // triangle (support 3, sum 0.4). Support beats closeness.
        let six = vec![
            vec![0.0, 0.1, 0.1, inf, inf, inf],
            vec![0.1, 0.0, inf, inf, inf, inf],
            vec![0.1, inf, 0.0, inf, inf, inf],
            vec![inf, inf, inf, 0.0, 0.2, 0.2],
            vec![inf, inf, inf, 0.2, 0.0, 0.2],
            vec![inf, inf, inf, 0.2, 0.2, 0.0],
        ];
        assert_eq!(cluster_support(&six, 0.5, 0), 2);
        assert_eq!(cluster_support(&six, 0.5, 3), 3);
        assert_eq!(choose_canonical(&six, 0.5), 3);
        // ...but the hub has as many agreements as the triangle's members and
        // disagrees with them: the choice is ambiguous (4 tied, degree 2).
        assert_eq!(ambiguous_top(&six, 0.5, 3), Some((4, 2)));
        // Ties among mutually agreeing positions are not ambiguous.
        assert_eq!(ambiguous_top(&d, 0.5, 0), None);
        assert_eq!(ambiguous_top(&hub, 0.5, 2), None);
        assert_eq!(ambiguous_top(&pairish, 0.5, 0), None);
    }

    #[test]
    fn pair_and_replica_counts() {
        assert_eq!(pair_count(0), 0);
        assert_eq!(pair_count(1), 0);
        assert_eq!(pair_count(2), 1);
        assert_eq!(pair_count(3), 3);
        assert_eq!(pair_count(16), 120);
        assert_eq!(replica_count(&IntegrityPolicy::None), 1);
        assert_eq!(
            replica_count(&IntegrityPolicy::Deterministic { replicas: 0 }),
            1
        );
        assert_eq!(
            replica_count(&IntegrityPolicy::Deterministic { replicas: 4 }),
            4
        );
    }

    fn metric_ref(kp: &IdentityKeyPair) -> MetricRef {
        MetricRef {
            plugin: format!("{}/m@0.1.0", kp.fingerprint_hex()).parse().unwrap(),
            publisher_key: *kp.public().as_bytes(),
            artifact_blake3: [3; 32],
        }
    }

    #[test]
    fn submit_validation_rejects_unusable_policies() {
        let v = verifier();
        let kp = IdentityKeyPair::generate();
        let sem = |replicas, quorum, threshold| IntegrityPolicy::SemanticEquivalent {
            replicas,
            quorum,
            metric: metric_ref(&kp),
            threshold,
        };
        for bad in [
            sem(1, 1, 0.1),
            sem(17, 1, 0.1),
            sem(3, 0, 0.1),
            sem(3, 4, 0.1),
            sem(3, 1, 0.0),
            sem(3, 1, -1.0),
            sem(3, 1, f64::NAN),
            sem(3, 1, f64::INFINITY),
            IntegrityPolicy::Deterministic { replicas: 17 },
        ] {
            assert!(
                matches!(
                    v.validate_submit(&bad),
                    Err(IntegrityError::InvalidPolicy(_))
                ),
                "{bad:?}"
            );
        }
        // Valid shape, but the publisher is not on this (empty) keyring.
        assert!(matches!(
            v.validate_submit(&sem(3, 2, 0.2)),
            Err(IntegrityError::MetricNotInKeyring { .. })
        ));
        assert!(matches!(
            v.validate_submit(&IntegrityPolicy::Attested { tee: "tdx".into() }),
            Err(IntegrityError::NotImplemented("Attested"))
        ));
        let env = v
            .validate_submit(&IntegrityPolicy::Deterministic { replicas: 3 })
            .unwrap();
        assert_eq!(
            env.hash(),
            policy_hash(&IntegrityPolicy::Deterministic { replicas: 3 })
        );
    }

    /// The size guard fires for an oversized replica even when the others are
    /// fine, names the offender, and penalises only it.
    #[tokio::test]
    async fn oversized_replica_is_terminal_and_penalised() {
        let v = verifier();
        let policy = IntegrityPolicy::Deterministic { replicas: 3 };
        let env = PolicyEnvelope::seal(&policy).unwrap();
        let h = env.hash();
        let t = task(policy, 8);
        let replicas = vec![
            ok(1, b"same", h),
            ok(2, &[0u8; 64], h),
            ReplicaResult {
                peer: peer(3),
                remote: true,
                outcome: Err(DispatchError::OutputSizeExceeded(
                    EntangleError::OutputSizeExceeded {
                        declared: 8,
                        actual: 4096,
                        peer: peer(3).to_hex(),
                    },
                )),
            },
        ];
        let err = v.accept(&t, &env, replicas).await.unwrap_err();
        match err {
            DispatchError::OutputSizeExceeded(EntangleError::OutputSizeExceeded {
                declared,
                actual,
                peer: p,
            }) => {
                assert_eq!((declared, actual), (8, 64));
                assert_eq!(p, peer(2).to_hex());
            }
            other => panic!("{other:?}"),
        }
        let rep = v.reputation();
        assert!(rep.get(&peer(2), PolicyKind::Deterministic) < INITIAL_SCORE);
        assert!(rep.get(&peer(3), PolicyKind::Deterministic) < INITIAL_SCORE);
        assert_eq!(rep.get(&peer(1), PolicyKind::Deterministic), INITIAL_SCORE);
    }

    #[tokio::test]
    async fn a_wrong_policy_echo_is_refused_and_penalised() {
        let v = verifier();
        let policy = IntegrityPolicy::None;
        let env = PolicyEnvelope::seal(&policy).unwrap();
        let other = policy_hash(&IntegrityPolicy::Deterministic { replicas: 2 });
        let err = v
            .accept(&task(policy, 1024), &env, vec![ok(1, b"x", other)])
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                DispatchError::Integrity(IntegrityError::PolicyHashMismatch { .. })
            ),
            "{err:?}"
        );
        assert!(v.reputation().get(&peer(1), PolicyKind::None) < INITIAL_SCORE);
    }

    #[tokio::test]
    async fn deterministic_accepts_identical_replicas_and_rewards_them() {
        let v = verifier();
        let policy = IntegrityPolicy::Deterministic { replicas: 3 };
        let env = PolicyEnvelope::seal(&policy).unwrap();
        let h = env.hash();
        let reps = vec![ok(1, b"42", h), ok(2, b"42", h), ok(3, b"42", h)];
        // Lower peer 2 first so the reward is observable.
        v.reputation().penalize(
            &peer(2),
            PolicyKind::Deterministic,
            ReputationReason::DisagreedWithQuorum,
        );
        let before = v.reputation().get(&peer(2), PolicyKind::Deterministic);
        let acc = v.accept(&task(policy, 1024), &env, reps).await.unwrap();
        assert_eq!(acc.output, b"42");
        assert_eq!(acc.chosen, 0);
        assert_eq!(acc.reports[0].status, ReplicaStatus::Canonical);
        assert_eq!(acc.reports[2].status, ReplicaStatus::Agreed);
        assert!(v.reputation().get(&peer(2), PolicyKind::Deterministic) > before);
    }

    #[tokio::test]
    async fn deterministic_mismatch_penalises_only_the_minority() {
        let v = verifier();
        let policy = IntegrityPolicy::Deterministic { replicas: 3 };
        let env = PolicyEnvelope::seal(&policy).unwrap();
        let h = env.hash();
        let reps = vec![ok(1, b"42", h), ok(2, b"41", h), ok(3, b"42", h)];
        let err = v.accept(&task(policy, 1024), &env, reps).await.unwrap_err();
        assert!(
            matches!(
                err,
                DispatchError::Integrity(IntegrityError::ReplicaHashMismatch { .. })
            ),
            "{err:?}"
        );
        let k = PolicyKind::Deterministic;
        assert!(v.reputation().get(&peer(2), k) < INITIAL_SCORE);
        assert_eq!(v.reputation().get(&peer(1), k), INITIAL_SCORE);
        assert_eq!(v.reputation().get(&peer(3), k), INITIAL_SCORE);
    }

    #[tokio::test]
    async fn missing_replicas_surface_the_underlying_failure() {
        let v = verifier();
        let policy = IntegrityPolicy::Deterministic { replicas: 2 };
        let env = PolicyEnvelope::seal(&policy).unwrap();
        let reps = vec![
            ok(1, b"42", env.hash()),
            ReplicaResult {
                peer: peer(2),
                remote: true,
                outcome: Err(DispatchError::RemoteTransport {
                    peer: peer(2),
                    reason: "unreachable".into(),
                }),
            },
        ];
        let err = v.accept(&task(policy, 1024), &env, reps).await.unwrap_err();
        assert!(
            matches!(err, DispatchError::RemoteTransport { .. }),
            "{err:?}"
        );
    }
}
