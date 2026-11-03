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
//! once — exactly one component instantiation per pair (ATC-INT-1). The task
//! is accepted iff at least `quorum` pairs have distance `< threshold`.
//!
//! The returned (canonical) output is the replica that
//!
//! 1. agrees (`distance < threshold`) with the most other replicas;
//! 2. on a tie, has the smallest sum of distances to the replicas it agrees
//!    with;
//! 3. on a further tie, comes first in canonical order (smallest output
//!    BLAKE3).
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
    /// For `SemanticEquivalent`: `(agreeing pairs, pairs compared)`.
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
                if ok.len() < 2 {
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
                let n = order.len();
                let mut dist = vec![vec![f64::INFINITY; n]; n];
                let mut agreeing = 0usize;
                let mut pairs = 0usize;
                for a in 0..n {
                    for b in (a + 1)..n {
                        let d = self
                            .metrics
                            .compare(metric, outputs[order[a]], outputs[order[b]])
                            .await?;
                        dist[a][b] = d;
                        dist[b][a] = d;
                        pairs += 1;
                        if d < *threshold {
                            agreeing += 1;
                        }
                    }
                }
                if agreeing < *quorum as usize {
                    return Err(IntegrityError::QuorumNotReached {
                        agreeing,
                        pairs,
                        required: *quorum,
                    }
                    .into());
                }

                let canonical_pos = choose_canonical(&dist, *threshold);
                let chosen = order[canonical_pos];
                for (pos, &idx) in order.iter().enumerate() {
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
/// are in canonical order): most agreements, then smallest sum of agreeing
/// distances, then lowest position.
pub fn choose_canonical(dist: &[Vec<f64>], threshold: f64) -> usize {
    let mut best = 0usize;
    let mut best_key: Option<(usize, f64)> = None;
    for (i, row) in dist.iter().enumerate() {
        let agreeing: Vec<f64> = row
            .iter()
            .enumerate()
            .filter(|&(j, d)| j != i && *d < threshold)
            .map(|(_, d)| *d)
            .collect();
        let degree = agreeing.len();
        let sum: f64 = agreeing.iter().sum();
        let better = match best_key {
            None => true,
            Some((bd, bs)) => degree > bd || (degree == bd && sum < bs),
        };
        if better {
            best = i;
            best_key = Some((degree, sum));
        }
    }
    best
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

    #[test]
    fn canonical_choice_prefers_degree_then_closeness_then_position() {
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
