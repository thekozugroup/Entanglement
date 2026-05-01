//! Integrity-policy enforcement (spec §7.5).
//!
//! Phase 1: local enforcement only. Cross-node replication arrives with the
//! Phase-2 scheduler.

use entangle_types::peer_id::PeerId;
use entangle_types::task::IntegrityPolicy;

/// Integrity enforcement errors.
///
/// Each variant maps to a stable error code in the ENTANGLE-E03xx range.
#[derive(Debug, thiserror::Error, Clone)]
pub enum IntegrityError {
    /// Two or more replicas returned different output hashes.
    #[error(
        "ENTANGLE-E0301: replicas mismatched (replica {replica} hash {got}, expected {expected})"
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
    /// The policy variant is not enforced in Phase 1.
    #[error("ENTANGLE-E0304: integrity policy {0} not implemented in Phase 1")]
    NotImplemented(&'static str),
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
