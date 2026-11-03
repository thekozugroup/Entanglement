//! Integrity-policy enforcement (spec §7.5).
//!
//! This module holds the policy checks that need nothing but bytes and peer
//! ids, plus [`IntegrityError`] — the single error type for integrity
//! verification across the stack. Replication across peers and the
//! `SemanticEquivalent` acceptance pipeline live in `entangle-scheduler`
//! (`entangle_scheduler::integrity`), because verification is the
//! **submitter's** job (§7.5 verifier-locality); the metric components that
//! pipeline runs are loaded by [`crate::metric::MetricRegistry`].

use entangle_types::peer_id::PeerId;
use entangle_types::task::IntegrityPolicy;

/// Integrity enforcement errors.
///
/// Each variant maps to a stable error code. This enum owns two blocks:
/// ENTANGLE-E0302–E0305 (the original local checks) and
/// ENTANGLE-E0306–E0349 (submitter-side verification: metrics, the policy
/// envelope, quorum). E0300–E0301 belong to
/// [`EntangleError`](entangle_types::errors::EntangleError) (task execution);
/// an oversized replica output is reported with that enum's E0300 — see the
/// range table in `entangle-types::errors` for the workspace-wide map.
#[derive(Debug, thiserror::Error, Clone)]
pub enum IntegrityError {
    /// Two or more replicas returned different output hashes.
    ///
    /// Carries `ENTANGLE-E0305`; it used `E0301` until that code was reserved
    /// for `EntangleError::TaskTimeout`.
    #[error(
        "ENTANGLE-E0305: replicas mismatched (replica {replica} hash {got}, expected {expected})"
    )]
    ReplicaHashMismatch {
        /// Zero-based index of the diverging replica.
        replica: usize,
        /// BLAKE3 hex of the diverging output.
        got: String,
        /// BLAKE3 hex of the canonical (replica 0) output.
        expected: String,
    },
    /// Fewer replicas were produced than the policy requires.
    #[error("ENTANGLE-E0302: insufficient replicas {actual} (policy required {required})")]
    InsufficientReplicas {
        /// Number of replicas actually collected.
        actual: usize,
        /// Number the policy demanded.
        required: u8,
    },
    /// The local peer is absent from the `TrustedExecutor` allowlist.
    #[error("ENTANGLE-E0303: TrustedExecutor allowlist did not include local peer {0}")]
    TrustedExecutorRefused(String),
    /// ENTANGLE-E0304: the policy needs hardware support this build does not
    /// have. Only `Attested` produces it: TEE attestation (SEV-SNP, TDX, Apple
    /// Secure Enclave, Nitro) is Phase 4+ per spec §7.5, so the variant exists
    /// on the wire for forward compatibility and is always refused.
    #[error(
        "ENTANGLE-E0304: integrity policy {0} is unsupported: it requires TEE attestation, \
         which no Entanglement build supports yet (spec §7.5: Phase 4+)"
    )]
    NotImplemented(&'static str),
    /// ENTANGLE-E0306: the policy can only be verified by the submitter's
    /// scheduler pipeline, not by the kernel on its own.
    ///
    /// `SemanticEquivalent` needs replicas on several peers and a signed metric
    /// component run on the submitter; submit it through
    /// `entangle_scheduler::Dispatcher`.
    #[error(
        "ENTANGLE-E0306: integrity policy {0} is verified by the submitter's scheduler \
         (entangle-scheduler Dispatcher), not by a bare kernel invocation"
    )]
    VerifierRequired(&'static str),
    /// ENTANGLE-E0307: the metric's publisher key is not on the submitter's
    /// keyring (spec §7.5 Rule 2, ATC-INT-2).
    #[error(
        "ENTANGLE-E0307: metric {metric} is signed by publisher {fingerprint}, \
         which is not in the submitter's keyring"
    )]
    MetricNotInKeyring {
        /// The metric plugin id.
        metric: String,
        /// Hex fingerprint of the untrusted publisher key.
        fingerprint: String,
    },
    /// ENTANGLE-E0308: a metric reference names one publisher in its plugin id
    /// and carries a different publisher's key.
    #[error(
        "ENTANGLE-E0308: metric reference {metric} is inconsistent: its publisher key \
         does not hash to the plugin id's publisher fingerprint"
    )]
    MetricRefInconsistent {
        /// The metric plugin id.
        metric: String,
    },
    /// ENTANGLE-E0309: no verified metric component with the referenced
    /// BLAKE3 is loaded on the submitter.
    #[error(
        "ENTANGLE-E0309: metric {metric} (blake3 {artifact}) is not loaded on this node; \
         load its signed package first"
    )]
    MetricUnavailable {
        /// The metric plugin id.
        metric: String,
        /// Hex BLAKE3 of the referenced component.
        artifact: String,
    },
    /// ENTANGLE-E0310: a metric package could not be loaded (bad manifest,
    /// bad signature, wrong tier, not a metric component).
    #[error("ENTANGLE-E0310: metric package {source_path} rejected: {reason}")]
    MetricLoad {
        /// Directory (or other label) the package came from.
        source_path: String,
        /// Why it was rejected.
        reason: String,
    },
    /// ENTANGLE-E0311: running the metric component failed (trap, timeout,
    /// resource limit).
    #[error("ENTANGLE-E0311: metric {metric} failed: {reason}")]
    MetricFailed {
        /// The metric plugin id.
        metric: String,
        /// The host error, rendered.
        reason: String,
    },
    /// ENTANGLE-E0312: the metric returned `NaN` or a negative distance,
    /// violating the `entangle:integrity/metric` contract.
    #[error(
        "ENTANGLE-E0312: metric {metric} violated its contract by returning {distance} \
         (distances must be >= 0; +inf means incomparable)"
    )]
    MetricContractViolation {
        /// The metric plugin id.
        metric: String,
        /// The offending value.
        distance: f64,
    },
    /// ENTANGLE-E0313: the policy's parameters are unusable (rejected at
    /// submit time, before anything is dispatched).
    #[error("ENTANGLE-E0313: invalid integrity policy: {0}")]
    InvalidPolicy(String),
    /// ENTANGLE-E0314: too few replica pairs agreed.
    #[error(
        "ENTANGLE-E0314: semantic quorum not reached: {agreeing} of {pairs} replica pairs \
         agreed (policy requires {required})"
    )]
    QuorumNotReached {
        /// Pairs whose distance was below the threshold, counted within the
        /// best-supported agreement cluster (the pairs that would back the
        /// returned output).
        agreeing: usize,
        /// Pairs compared.
        pairs: usize,
        /// The policy's quorum.
        required: u8,
    },
    /// ENTANGLE-E0315: a replica's echoed policy hash differs from the hash
    /// the submitter dispatched (INV-INT-1).
    #[error(
        "ENTANGLE-E0315: peer {peer} observed policy hash {observed}, \
         but the task was dispatched with {expected}"
    )]
    PolicyHashMismatch {
        /// The replica's executor.
        peer: String,
        /// The hash the submitter dispatched.
        expected: String,
        /// The hash the replica reported.
        observed: String,
    },
    /// ENTANGLE-E0316: a control frame tried to change the policy of an
    /// in-flight task (INV-INT-1, ATC-INT-3).
    #[error(
        "ENTANGLE-E0316: peer {peer} refused to change the integrity policy of in-flight \
         task {task_id}: the policy is immutable for the task's lifetime"
    )]
    PolicyMutation {
        /// The executor that refused.
        peer: String,
        /// The task whose policy the frame tried to change.
        task_id: String,
    },
    /// ENTANGLE-E0317: canonical policy bytes could not be decoded.
    #[error("ENTANGLE-E0317: malformed canonical integrity policy: {0}")]
    PolicyEncoding(String),
    /// ENTANGLE-E0318: the best-supported `SemanticEquivalent` outputs
    /// disagree with each other — two or more groups of replicas agree
    /// internally, equally well, but not across groups — so there is no single
    /// answer to return. Refused rather than settled by a tie-break, and
    /// nobody is blamed.
    #[error(
        "ENTANGLE-E0318: semantic agreement is ambiguous: {candidates} replica outputs each \
         agree with {agreements} other replica(s), but not all with each other; no single \
         answer is best supported, so none is returned"
    )]
    AmbiguousAgreement {
        /// How many replicas share the highest agreement count.
        candidates: usize,
        /// That agreement count (other replicas within threshold).
        agreements: usize,
    },
}

/// The output of one replica invocation together with its BLAKE3 digest.
#[derive(Clone, Debug)]
pub struct ReplicaOutput {
    /// Raw bytes returned by the plugin.
    pub bytes: Vec<u8>,
    /// BLAKE3 digest of `bytes`.
    pub blake3: [u8; 32],
}

/// Verify N replica outputs satisfy `IntegrityPolicy::Deterministic`.
///
/// Returns `&replicas[0]` (the canonical output) on success.
///
/// # Errors
/// - [`IntegrityError::InsufficientReplicas`] when fewer than `required` were supplied.
/// - [`IntegrityError::ReplicaHashMismatch`] when any replica diverges from replica 0.
pub fn verify_deterministic(
    replicas: &[ReplicaOutput],
    required: u8,
) -> Result<&ReplicaOutput, IntegrityError> {
    if (replicas.len() as u8) < required {
        return Err(IntegrityError::InsufficientReplicas {
            actual: replicas.len(),
            required,
        });
    }
    let expected = replicas[0].blake3;
    let expected_hex = hex::encode(expected);
    for (i, r) in replicas.iter().enumerate().skip(1) {
        if r.blake3 != expected {
            return Err(IntegrityError::ReplicaHashMismatch {
                replica: i,
                got: hex::encode(r.blake3),
                expected: expected_hex.clone(),
            });
        }
    }
    Ok(&replicas[0])
}

/// Validate that a `TrustedExecutor` allowlist contains `local_peer`.
///
/// Returns `Ok(())` immediately if `policy` is not `TrustedExecutor` (no-op).
///
/// # Errors
/// [`IntegrityError::TrustedExecutorRefused`] when the local peer is absent.
pub fn check_trusted_executor(
    policy: &IntegrityPolicy,
    local_peer: &PeerId,
) -> Result<(), IntegrityError> {
    let IntegrityPolicy::TrustedExecutor { allowlist } = policy else {
        return Ok(()); // not our policy; nothing to check
    };
    if allowlist.contains(local_peer) {
        Ok(())
    } else {
        Err(IntegrityError::TrustedExecutorRefused(local_peer.to_hex()))
    }
}
