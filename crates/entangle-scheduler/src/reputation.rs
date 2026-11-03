//! Per-peer correctness reputation (spec §7.5 Layer 3).
//!
//! > EWMA of `correct / total` per peer per policy variant. Thresholds
//! > 0.95 / 0.90 / 0.80. Reputation is maintained *separately* per policy: a
//! > peer can be trusted for `Deterministic` jobs and not for
//! > `SemanticEquivalent`, and that asymmetry is preserved.
//!
//! Each `(peer, policy kind)` pair carries an exponentially weighted moving
//! average of a per-task correctness indicator (1 = the peer's replica was
//! accepted, 0 = it was not), plus the raw counts for audit:
//!
//! ```text
//! score' = (1 - alpha) * score + alpha * x        x ∈ {0, 1}
//! ```
//!
//! A peer nobody has observed starts at [`INITIAL_SCORE`] (1.0): placement
//! only ever targets peers this node already trusts (the scheduler allowlist),
//! so the prior is "trusted until shown otherwise". With the default
//! `alpha = 0.1`, one failure takes a fresh peer to 0.90 ([`ReputationTier::Good`]),
//! two to 0.81 ([`ReputationTier::Probation`]), three to 0.729
//! ([`ReputationTier::Excluded`]) — and an excluded peer is no longer chosen as
//! a replica target for that policy variant.
//!
//! What lowers a score, and why, is a [`ReputationReason`]: an oversized
//! output (INV-INT-2), a policy-hash echo that does not match (INV-INT-1), a
//! replica that disagreed with the accepted quorum, or an output the metric
//! could not compare with any other replica's.
//!
//! The store is in-memory and per-node: it records this submitter's own
//! observations and is never gossiped.

use std::collections::HashMap;

use entangle_types::peer_id::PeerId;
use entangle_types::task::PolicyKind;
use parking_lot::RwLock;

/// Score of a peer with no recorded observations.
pub const INITIAL_SCORE: f64 = 1.0;
/// Default EWMA smoothing factor.
pub const DEFAULT_ALPHA: f64 = 0.1;
/// At or above: [`ReputationTier::Trusted`].
pub const TRUSTED_THRESHOLD: f64 = 0.95;
/// At or above (and below trusted): [`ReputationTier::Good`].
pub const GOOD_THRESHOLD: f64 = 0.90;
/// At or above (and below good): [`ReputationTier::Probation`]. Below it:
/// [`ReputationTier::Excluded`].
pub const PROBATION_THRESHOLD: f64 = 0.80;

/// Coarse standing derived from a score and the spec thresholds.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReputationTier {
    /// `score < 0.80` — not selected as a replica target for this policy.
    Excluded,
    /// `0.80 <= score < 0.90`.
    Probation,
    /// `0.90 <= score < 0.95`.
    Good,
    /// `score >= 0.95`.
    Trusted,
}

impl ReputationTier {
    /// The tier a `score` falls in.
    pub fn of(score: f64) -> Self {
        if score >= TRUSTED_THRESHOLD {
            Self::Trusted
        } else if score >= GOOD_THRESHOLD {
            Self::Good
        } else if score >= PROBATION_THRESHOLD {
            Self::Probation
        } else {
            Self::Excluded
        }
    }
}

/// Why a peer's score was lowered.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ReputationReason {
    /// Its result exceeded the task's `max_output_bytes` (INV-INT-2).
    OversizedOutput,
    /// Its echoed policy hash differed from the dispatched one (INV-INT-1).
    PolicyHashMismatch,
    /// Its replica disagreed with the accepted quorum / majority.
    DisagreedWithQuorum,
    /// Every metric comparison involving its output failed (the metric
    /// trapped, timed out, ran out of memory or broke its contract) while
    /// other replicas' outputs compared fine.
    IncomparableOutput,
    /// As a stream executor, it sent a chunk (or `End`) whose signature or
    /// sequence did not verify (ATC-STR-3).
    BadChunkSignature,
    /// As a stream executor, it broke the stream protocol: data without
    /// credit, or a frame invalid in the stream's state.
    StreamProtocolViolation,
}

impl ReputationReason {
    /// Stable label for logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OversizedOutput => "oversized-output",
            Self::PolicyHashMismatch => "policy-hash-mismatch",
            Self::DisagreedWithQuorum => "disagreed-with-quorum",
            Self::IncomparableOutput => "incomparable-output",
            Self::BadChunkSignature => "bad-chunk-signature",
            Self::StreamProtocolViolation => "stream-protocol-violation",
        }
    }
}

/// One `(peer, policy kind)` record.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct PeerRecord {
    /// Current EWMA score in `[0, 1]`.
    pub score: f64,
    /// Observations recorded as correct.
    pub correct: u64,
    /// All observations recorded.
    pub total: u64,
}

impl Default for PeerRecord {
    fn default() -> Self {
        Self {
            score: INITIAL_SCORE,
            correct: 0,
            total: 0,
        }
    }
}

/// In-memory reputation store. Cheap to share behind an `Arc`.
#[derive(Debug)]
pub struct ReputationStore {
    alpha: f64,
    records: RwLock<HashMap<(PeerId, PolicyKind), PeerRecord>>,
}

impl Default for ReputationStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ReputationStore {
    /// A store with [`DEFAULT_ALPHA`].
    pub fn new() -> Self {
        Self::with_alpha(DEFAULT_ALPHA)
    }

    /// A store with a custom smoothing factor, clamped to `(0, 1]` (a
    /// non-finite or non-positive value falls back to [`DEFAULT_ALPHA`]).
    pub fn with_alpha(alpha: f64) -> Self {
        let alpha = if alpha.is_finite() && alpha > 0.0 {
            alpha.min(1.0)
        } else {
            DEFAULT_ALPHA
        };
        Self {
            alpha,
            records: RwLock::new(HashMap::new()),
        }
    }

    /// The peer's score for `kind` ([`INITIAL_SCORE`] if never observed).
    pub fn get(&self, peer: &PeerId, kind: PolicyKind) -> f64 {
        self.record(peer, kind).score
    }

    /// The peer's full record for `kind` (a default record if never observed).
    pub fn record(&self, peer: &PeerId, kind: PolicyKind) -> PeerRecord {
        self.records
            .read()
            .get(&(*peer, kind))
            .copied()
            .unwrap_or_default()
    }

    /// The peer's tier for `kind`.
    pub fn tier(&self, peer: &PeerId, kind: PolicyKind) -> ReputationTier {
        ReputationTier::of(self.get(peer, kind))
    }

    /// Whether the peer may be chosen as a replica target for `kind`.
    pub fn is_eligible(&self, peer: &PeerId, kind: PolicyKind) -> bool {
        self.tier(peer, kind) != ReputationTier::Excluded
    }

    /// Record that the peer's replica was accepted. Returns the new score.
    pub fn record_correct(&self, peer: &PeerId, kind: PolicyKind) -> f64 {
        self.observe(peer, kind, true)
    }

    /// Record that the peer misbehaved. Returns the new (strictly lower,
    /// unless already 0) score.
    pub fn penalize(&self, peer: &PeerId, kind: PolicyKind, reason: ReputationReason) -> f64 {
        let score = self.observe(peer, kind, false);
        tracing::info!(
            target: "entangle::telemetry",
            event = "ReputationPenalty",
            peer_id = %peer,
            policy = %kind,
            reason = reason.as_str(),
            score,
            "peer reputation lowered"
        );
        score
    }

    fn observe(&self, peer: &PeerId, kind: PolicyKind, correct: bool) -> f64 {
        let mut records = self.records.write();
        let rec = records.entry((*peer, kind)).or_default();
        let x = if correct { 1.0 } else { 0.0 };
        rec.score = ((1.0 - self.alpha) * rec.score + self.alpha * x).clamp(0.0, 1.0);
        rec.total += 1;
        if correct {
            rec.correct += 1;
        }
        rec.score
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(b: u8) -> PeerId {
        PeerId::from_public_key_bytes(&[b; 32])
    }

    #[test]
    fn an_unknown_peer_starts_trusted() {
        let store = ReputationStore::new();
        assert_eq!(
            store.get(&peer(1), PolicyKind::Deterministic),
            INITIAL_SCORE
        );
        assert_eq!(
            store.tier(&peer(1), PolicyKind::Deterministic),
            ReputationTier::Trusted
        );
        assert_eq!(store.record(&peer(1), PolicyKind::Deterministic).total, 0);
    }

    #[test]
    fn penalties_walk_down_the_spec_thresholds() {
        let store = ReputationStore::new();
        let p = peer(2);
        let k = PolicyKind::SemanticEquivalent;
        let r = ReputationReason::DisagreedWithQuorum;
        let s1 = store.penalize(&p, k, r);
        assert!((s1 - 0.9).abs() < 1e-12, "{s1}");
        assert_eq!(store.tier(&p, k), ReputationTier::Good);
        let s2 = store.penalize(&p, k, r);
        assert!((s2 - 0.81).abs() < 1e-12, "{s2}");
        assert_eq!(store.tier(&p, k), ReputationTier::Probation);
        assert!(store.is_eligible(&p, k));
        let s3 = store.penalize(&p, k, r);
        assert!(s3 < PROBATION_THRESHOLD, "{s3}");
        assert_eq!(store.tier(&p, k), ReputationTier::Excluded);
        assert!(!store.is_eligible(&p, k));
        let rec = store.record(&p, k);
        assert_eq!((rec.correct, rec.total), (0, 3));
    }

    #[test]
    fn correct_results_recover_a_score() {
        let store = ReputationStore::new();
        let p = peer(3);
        let k = PolicyKind::Deterministic;
        let low = store.penalize(&p, k, ReputationReason::OversizedOutput);
        let up = store.record_correct(&p, k);
        assert!(up > low);
        assert!(up <= 1.0);
        let rec = store.record(&p, k);
        assert_eq!((rec.correct, rec.total), (1, 2));
    }

    /// Spec: reputation is kept separately per policy variant.
    #[test]
    fn reputation_is_per_policy_variant() {
        let store = ReputationStore::new();
        let p = peer(4);
        for _ in 0..5 {
            store.penalize(
                &p,
                PolicyKind::SemanticEquivalent,
                ReputationReason::DisagreedWithQuorum,
            );
        }
        assert_eq!(
            store.tier(&p, PolicyKind::SemanticEquivalent),
            ReputationTier::Excluded
        );
        assert_eq!(store.get(&p, PolicyKind::Deterministic), INITIAL_SCORE);
        assert!(store.is_eligible(&p, PolicyKind::Deterministic));
        // And per peer.
        assert_eq!(
            store.get(&peer(5), PolicyKind::SemanticEquivalent),
            INITIAL_SCORE
        );
    }

    #[test]
    fn tier_boundaries_are_inclusive_lower_bounds() {
        assert_eq!(ReputationTier::of(1.0), ReputationTier::Trusted);
        assert_eq!(ReputationTier::of(0.95), ReputationTier::Trusted);
        assert_eq!(ReputationTier::of(0.9499), ReputationTier::Good);
        assert_eq!(ReputationTier::of(0.90), ReputationTier::Good);
        assert_eq!(ReputationTier::of(0.8999), ReputationTier::Probation);
        assert_eq!(ReputationTier::of(0.80), ReputationTier::Probation);
        assert_eq!(ReputationTier::of(0.7999), ReputationTier::Excluded);
        assert_eq!(ReputationTier::of(0.0), ReputationTier::Excluded);
    }

    #[test]
    fn a_bad_alpha_falls_back_to_the_default() {
        for alpha in [f64::NAN, -1.0, 0.0, f64::INFINITY] {
            let store = ReputationStore::with_alpha(alpha);
            let s = store.penalize(
                &peer(6),
                PolicyKind::None,
                ReputationReason::OversizedOutput,
            );
            assert!((s - 0.9).abs() < 1e-12, "alpha {alpha}: {s}");
        }
        let store = ReputationStore::with_alpha(5.0);
        assert_eq!(
            store.penalize(
                &peer(6),
                PolicyKind::None,
                ReputationReason::OversizedOutput
            ),
            0.0,
            "alpha is clamped to 1"
        );
    }
}
