//! Layer-2 deterministic-replay spot-check (spec §7.5).
//!
//! > Applies to `Deterministic` and `SemanticEquivalent` tasks. The scheduler
//! > spot-checks 1% of completed tasks. Attestation failures downrank the
//! > offending peer.
//!
//! After the [`Dispatcher`](crate::Dispatcher) has **accepted** a
//! `Deterministic` or `SemanticEquivalent` task and returned its result, it
//! samples the task with probability [`SpotCheckConfig::probability`]
//! (1 % by default in the daemon; off in a library dispatcher until
//! [`Dispatcher::with_spot_checks`](crate::Dispatcher::with_spot_checks)).
//! A sampled task is run once more, in the background, on an executor that
//! produced none of its replicas:
//!
//! * the best-ranked live remote worker that ran no replica of the task and
//!   whose reputation for the policy is not `Excluded`;
//! * failing that, this node's own kernel, if it has the plugin loaded;
//! * failing that, nobody: the check is skipped (`skipped_no_checker`).
//!
//! An executor whose re-run produces nothing comparable — workers do not
//! advertise their plugins, so one that does not have it is an ordinary
//! case; or it is unreachable, or breaks a guard — does not end the check:
//! the next one in that order is asked, up to [`MAX_EXECUTORS`]
//! ([`SpotCheckRecord::unavailable`] lists who was skipped and why).
//!
//! The re-run passes the same guards as a replica (output size, then the
//! echoed policy hash) and is then compared with the accepted output — on
//! the submitter, as always:
//!
//! * `Deterministic`: byte-identical (BLAKE3);
//! * `SemanticEquivalent`: the policy's metric distance between the
//!   accepted output and the re-run's, which must be `< threshold`. The two
//!   are compared in acceptance's canonical pair order (lower output BLAKE3
//!   first, [`crate::integrity::canonical_operands`]), so an asymmetric
//!   metric gives the distance acceptance would give the same pair.
//!
//! A mismatch is an **attestation failure** ([`SpotCheckVerdict::Mismatch`],
//! `ENTANGLE-E0319`): every remote replica that produced or agreed with the
//! accepted output loses reputation for that policy variant
//! ([`ReputationReason::SpotCheckMismatch`](crate::ReputationReason::SpotCheckMismatch)),
//! a `SpotCheckAttestationFailure` warning is emitted at
//! [`TELEMETRY_TARGET`], the
//! `entangle_integrity_spot_checks_total{outcome="mismatch"}` counter goes
//! up, and the record is kept in the dispatcher's audit log
//! ([`SpotChecker::recent`]).
//!
//! # Detective, not preventive
//!
//! The spot-check runs **after** the result was returned to the caller and
//! never changes it: a caller that wants a stronger guarantee for one task
//! asks for more replicas. What a spot-check does is make lying expensive
//! over time — colluding replicas that agree on a wrong answer are caught at
//! the sampling rate and lose standing until placement stops choosing them.
//! The verdict trusts the checker's re-run; that is why a remote checker
//! must itself be in good standing, and why this node's own kernel is the
//! fallback.
//!
//! # What is never spot-checked
//!
//! * `None`, `TrustedExecutor` and `Attested` tasks — the spec exempts them
//!   (and a `TrustedExecutor` task may only run on its allowlist);
//! * a task whose accepted output this node already reproduced on its own
//!   kernel (a local replica produced or agreed with it): there is nothing
//!   left to attest.
//!
//! # A local replica that was outvoted
//!
//! When this node's own kernel ran a replica and the remote majority
//! outvoted it (its status is `disagreed`), its output — already in hand —
//! *is* the re-run of a sampled task: nothing runs again, and no other
//! executor is needed ([`SpotCheckRecord::reused_replica`]). The trusted
//! kernel contradicting the accepted output is the strongest evidence a
//! spot-check can have.
//!
//! # Bounded
//!
//! At most [`SpotCheckConfig::max_concurrent`] spot-checks run at once. A
//! sampled task that finds them all busy is skipped and counted
//! (`skipped_saturated`), never queued, so a burst of tasks cannot build an
//! unbounded backlog of re-runs (or of accepted outputs held for comparison).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use entangle_runtime::IntegrityError;
use entangle_types::peer_id::PeerId;
use entangle_types::plugin_id::PluginId;
use entangle_types::task::{PolicyKind, TaskId};
use parking_lot::Mutex;
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};

use crate::integrity::TELEMETRY_TARGET;
use crate::work_unit::PolicyHash;

/// The spec's sampling rate: 1 % of accepted tasks.
pub const DEFAULT_PROBABILITY: f64 = 0.01;

/// Default bound on spot-checks running at once.
pub const DEFAULT_MAX_CONCURRENT: usize = 4;

/// How many finished spot-checks [`SpotChecker::recent`] keeps.
pub const AUDIT_CAPACITY: usize = 256;

/// Most executors one spot-check asks to re-run its task: one that cannot
/// produce a comparable re-run (the plugin is not installed there, it is
/// unreachable, it broke a guard) is followed by the next eligible one, up
/// to this many, so a single unusable checker cannot switch Layer 2 off.
pub const MAX_EXECUTORS: usize = 4;

/// The `event` field of the warning emitted for an attestation failure.
pub const ATTESTATION_FAILURE_EVENT: &str = "SpotCheckAttestationFailure";

/// How often, and how many at once.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SpotCheckConfig {
    /// Probability that an eligible accepted task is re-run, in `[0, 1]`:
    /// `0` never, `1` always. Values outside the range are clamped; `NaN`
    /// counts as `0`.
    pub probability: f64,
    /// Most spot-checks running at once (at least 1).
    pub max_concurrent: usize,
}

impl Default for SpotCheckConfig {
    fn default() -> Self {
        Self {
            probability: DEFAULT_PROBABILITY,
            max_concurrent: DEFAULT_MAX_CONCURRENT,
        }
    }
}

impl SpotCheckConfig {
    /// The default bound with sampling probability `probability`.
    pub fn with_probability(probability: f64) -> Self {
        Self {
            probability,
            ..Self::default()
        }
    }

    /// The probability clamped into `[0, 1]` (`NaN` is `0`) and a bound of at
    /// least 1.
    pub fn normalized(self) -> Self {
        let probability = if self.probability.is_nan() {
            0.0
        } else {
            self.probability.clamp(0.0, 1.0)
        };
        Self {
            probability,
            max_concurrent: self.max_concurrent.max(1),
        }
    }
}

/// Why a task is not eligible for a spot-check at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exemption {
    /// Its policy is `None`, `TrustedExecutor` or `Attested` (spec §7.5).
    Policy,
    /// This node's own kernel produced or agreed with the accepted output.
    ReproducedLocally,
}

/// Why a sampled task was not re-run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// [`SpotCheckConfig::max_concurrent`] spot-checks were already running.
    Saturated,
    /// No executor other than the task's replicas could run it.
    NoChecker,
}

/// What the dispatcher decided about the spot-check of one accepted task,
/// at the moment it returned the result.
#[derive(Clone, Debug)]
pub enum SpotCheck {
    /// Spot-checks are off on this dispatcher (none configured, or
    /// probability 0).
    Disabled,
    /// The task is not eligible.
    Exempt(Exemption),
    /// Eligible, but not sampled this time.
    NotSampled,
    /// Sampled, but not re-run (counted in
    /// `entangle_integrity_spot_checks_total`).
    Skipped(SkipReason),
    /// Being re-run in the background; [`SpotCheckHandle::outcome`] waits
    /// for the verdict.
    Scheduled(SpotCheckHandle),
}

impl SpotCheck {
    /// Stable label: `disabled`, `exempt-policy`, `exempt-reproduced-locally`,
    /// `not-sampled`, `skipped-saturated`, `skipped-no-checker`, `scheduled`.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Exempt(Exemption::Policy) => "exempt-policy",
            Self::Exempt(Exemption::ReproducedLocally) => "exempt-reproduced-locally",
            Self::NotSampled => "not-sampled",
            Self::Skipped(SkipReason::Saturated) => "skipped-saturated",
            Self::Skipped(SkipReason::NoChecker) => "skipped-no-checker",
            Self::Scheduled(_) => "scheduled",
        }
    }

    /// The handle of a scheduled spot-check.
    pub fn handle(&self) -> Option<&SpotCheckHandle> {
        match self {
            Self::Scheduled(h) => Some(h),
            _ => None,
        }
    }
}

/// Waits for the verdict of one scheduled spot-check. Cheap to clone.
#[derive(Clone, Debug)]
pub struct SpotCheckHandle {
    rx: watch::Receiver<Option<Arc<SpotCheckRecord>>>,
}

impl SpotCheckHandle {
    /// A handle and the sender its spot-check reports through.
    pub(crate) fn channel() -> (watch::Sender<Option<Arc<SpotCheckRecord>>>, Self) {
        let (tx, rx) = watch::channel(None);
        (tx, Self { rx })
    }

    /// The verdict, once the re-run and comparison are done. `None` if the
    /// spot-check was abandoned (its runtime shut down first).
    pub async fn outcome(&self) -> Option<Arc<SpotCheckRecord>> {
        let mut rx = self.rx.clone();
        let done = rx.wait_for(Option::is_some).await.ok()?;
        done.clone()
    }

    /// The verdict if it is already in.
    pub fn try_outcome(&self) -> Option<Arc<SpotCheckRecord>> {
        self.rx.borrow().clone()
    }
}

/// How a finished spot-check came out.
#[derive(Clone, Debug)]
pub enum SpotCheckVerdict {
    /// The re-run reproduced the accepted output.
    Confirmed,
    /// The re-run did not reproduce it: an attestation failure
    /// ([`IntegrityError::SpotCheckMismatch`], `ENTANGLE-E0319`).
    Mismatch(IntegrityError),
    /// The re-run produced nothing comparable (it failed, was oversized,
    /// echoed another policy hash, or the metric could not compare it):
    /// nobody behind the accepted output is blamed.
    Inconclusive(String),
}

impl SpotCheckVerdict {
    /// Stable label (the metric `outcome`): `confirmed`, `mismatch`,
    /// `inconclusive`.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Mismatch(_) => "mismatch",
            Self::Inconclusive(_) => "inconclusive",
        }
    }
}

/// The audit record of one finished spot-check.
#[derive(Clone, Debug)]
pub struct SpotCheckRecord {
    /// The task.
    pub task_id: TaskId,
    /// Its plugin.
    pub plugin: PluginId,
    /// Its policy variant.
    pub policy: PolicyKind,
    /// Its policy hash `H` (INV-INT-1).
    pub policy_hash: PolicyHash,
    /// Who re-ran it.
    pub checker: PeerId,
    /// Whether the checker is another node (`false`: this node's kernel).
    pub checker_remote: bool,
    /// BLAKE3 of the accepted output.
    pub accepted_blake3: [u8; 32],
    /// BLAKE3 of the re-run's output, when it produced one.
    pub rerun_blake3: Option<[u8; 32]>,
    /// For `SemanticEquivalent`: the metric distance between the two.
    pub distance: Option<f64>,
    /// The remote replicas that produced or agreed with the accepted output.
    pub implicated: Vec<PeerId>,
    /// Who lost reputation because of this check: the implicated replicas
    /// on a mismatch, or a remote checker that broke a guard.
    pub penalised: Vec<PeerId>,
    /// The checker's output is the one its own replica of the task already
    /// produced — this node's kernel, outvoted at acceptance — so nothing
    /// ran again.
    pub reused_replica: bool,
    /// Executors asked to re-run the task before `checker` that produced
    /// nothing comparable (the re-run failed — e.g. the plugin is not
    /// installed there — was oversized, or echoed another policy hash),
    /// with why. The check moved on to the next eligible executor.
    pub unavailable: Vec<(PeerId, String)>,
    /// The verdict.
    pub verdict: SpotCheckVerdict,
}

impl SpotCheckRecord {
    /// Emit the structured `SpotCheckAttestationFailure` warning at
    /// [`TELEMETRY_TARGET`] (only for a [`SpotCheckVerdict::Mismatch`]).
    pub fn emit_if_mismatch(&self) {
        let SpotCheckVerdict::Mismatch(error) = &self.verdict else {
            return;
        };
        let penalised = self
            .penalised
            .iter()
            .map(PeerId::to_hex)
            .collect::<Vec<_>>()
            .join(",");
        tracing::warn!(
            target: TELEMETRY_TARGET,
            event = ATTESTATION_FAILURE_EVENT,
            task_id = %self.task_id,
            plugin = %self.plugin,
            policy = %self.policy,
            policy_hash = %self.policy_hash,
            checker = %self.checker,
            checker_remote = self.checker_remote,
            accepted_blake3 = %hex::encode(self.accepted_blake3),
            rerun_blake3 = %self.rerun_blake3.map(hex::encode).unwrap_or_default(),
            distance = self.distance.unwrap_or(f64::NAN),
            penalised = %penalised,
            error = %error,
            "spot-check: an accepted result was not reproduced on another executor; \
             the replicas behind it lose reputation (the result already returned stands)"
        );
    }
}

/// Running totals of [`SpotChecker`] decisions and verdicts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SpotCheckStats {
    /// Re-runs started.
    pub scheduled: u64,
    /// Re-runs that reproduced the accepted output.
    pub confirmed: u64,
    /// Attestation failures.
    pub mismatched: u64,
    /// Re-runs that produced nothing comparable.
    pub inconclusive: u64,
    /// Sampled tasks skipped because the bound was reached.
    pub skipped_saturated: u64,
    /// Sampled tasks skipped because nobody else could run them.
    pub skipped_no_checker: u64,
}

#[derive(Debug, Default)]
struct Counters {
    scheduled: AtomicU64,
    confirmed: AtomicU64,
    mismatched: AtomicU64,
    inconclusive: AtomicU64,
    skipped_saturated: AtomicU64,
    skipped_no_checker: AtomicU64,
}

/// A dispatcher's spot-check state: the sampling rate, the concurrency
/// bound, running totals and the audit log of recent verdicts.
#[derive(Debug)]
pub struct SpotChecker {
    config: SpotCheckConfig,
    permits: Arc<Semaphore>,
    counters: Counters,
    log: Mutex<VecDeque<Arc<SpotCheckRecord>>>,
}

impl SpotChecker {
    /// A checker for `config` (normalised, see
    /// [`SpotCheckConfig::normalized`]).
    pub fn new(config: SpotCheckConfig) -> Self {
        let config = config.normalized();
        Self {
            permits: Arc::new(Semaphore::new(config.max_concurrent)),
            config,
            counters: Counters::default(),
            log: Mutex::new(VecDeque::new()),
        }
    }

    /// The configuration in force.
    pub fn config(&self) -> SpotCheckConfig {
        self.config
    }

    /// Whether spot-checks can ever run (probability above 0).
    pub fn enabled(&self) -> bool {
        self.config.probability > 0.0
    }

    /// Draw once: `true` with the configured probability.
    pub fn sample(&self) -> bool {
        let p = self.config.probability;
        if p >= 1.0 {
            return true;
        }
        p > 0.0 && unit_random() < p
    }

    /// Spot-checks running right now.
    pub fn in_flight(&self) -> usize {
        self.config
            .max_concurrent
            .saturating_sub(self.permits.available_permits())
    }

    /// A slot for one more spot-check, or `None` (and counted) when the
    /// bound is reached.
    pub(crate) fn try_begin(&self) -> Option<OwnedSemaphorePermit> {
        let permit = Arc::clone(&self.permits).try_acquire_owned().ok();
        if permit.is_none() {
            self.counters
                .skipped_saturated
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.counters.scheduled.fetch_add(1, Ordering::Relaxed);
        }
        permit
    }

    /// Count a sampled task nobody else could run.
    pub(crate) fn note_no_checker(&self) {
        self.counters
            .skipped_no_checker
            .fetch_add(1, Ordering::Relaxed);
    }

    /// File a finished spot-check: totals and the bounded audit log.
    pub(crate) fn record(&self, record: Arc<SpotCheckRecord>) {
        let counter = match record.verdict {
            SpotCheckVerdict::Confirmed => &self.counters.confirmed,
            SpotCheckVerdict::Mismatch(_) => &self.counters.mismatched,
            SpotCheckVerdict::Inconclusive(_) => &self.counters.inconclusive,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        let mut log = self.log.lock();
        if log.len() == AUDIT_CAPACITY {
            log.pop_front();
        }
        log.push_back(record);
    }

    /// The most recent finished spot-checks (at most [`AUDIT_CAPACITY`]),
    /// oldest first.
    pub fn recent(&self) -> Vec<Arc<SpotCheckRecord>> {
        self.log.lock().iter().cloned().collect()
    }

    /// Running totals.
    pub fn stats(&self) -> SpotCheckStats {
        let c = &self.counters;
        SpotCheckStats {
            scheduled: c.scheduled.load(Ordering::Relaxed),
            confirmed: c.confirmed.load(Ordering::Relaxed),
            mismatched: c.mismatched.load(Ordering::Relaxed),
            inconclusive: c.inconclusive.load(Ordering::Relaxed),
            skipped_saturated: c.skipped_saturated.load(Ordering::Relaxed),
            skipped_no_checker: c.skipped_no_checker.load(Ordering::Relaxed),
        }
    }
}

/// A uniform draw from `[0, 1)` with 53 bits of OS randomness (the
/// random bytes of a v4 UUID: bytes 9..16 carry no version or variant bits).
fn unit_random() -> f64 {
    let bytes = uuid::Uuid::new_v4().into_bytes();
    let mut x = 0u64;
    for b in &bytes[9..16] {
        x = (x << 8) | u64::from(*b);
    }
    // 56 random bits; keep 53, the f64 mantissa.
    (x >> 3) as f64 / (1u64 << 53) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_configuration_is_normalised() {
        let c = SpotCheckConfig {
            probability: 7.0,
            max_concurrent: 0,
        }
        .normalized();
        assert_eq!((c.probability, c.max_concurrent), (1.0, 1));
        assert_eq!(
            SpotCheckConfig::with_probability(-1.0)
                .normalized()
                .probability,
            0.0
        );
        assert_eq!(
            SpotCheckConfig::with_probability(f64::NAN)
                .normalized()
                .probability,
            0.0
        );
        assert_eq!(SpotCheckConfig::default().probability, DEFAULT_PROBABILITY);
    }

    #[test]
    fn probability_zero_never_samples_and_one_always_does() {
        let never = SpotChecker::new(SpotCheckConfig::with_probability(0.0));
        let always = SpotChecker::new(SpotCheckConfig::with_probability(1.0));
        assert!(!never.enabled());
        for _ in 0..1_000 {
            assert!(!never.sample());
            assert!(always.sample());
        }
    }

    #[test]
    fn sampling_follows_the_probability() {
        let checker = SpotChecker::new(SpotCheckConfig::with_probability(0.25));
        let hits = (0..20_000).filter(|_| checker.sample()).count();
        // 5000 expected; sigma ~61, so this band is ~16 sigma wide.
        assert!((4_000..6_000).contains(&hits), "{hits}");
        for _ in 0..10_000 {
            let u = unit_random();
            assert!((0.0..1.0).contains(&u), "{u}");
        }
    }

    #[test]
    fn the_bound_is_enforced_and_saturation_is_counted() {
        let checker = SpotChecker::new(SpotCheckConfig {
            probability: 1.0,
            max_concurrent: 2,
        });
        let a = checker.try_begin().expect("first slot");
        let b = checker.try_begin().expect("second slot");
        assert_eq!(checker.in_flight(), 2);
        assert!(checker.try_begin().is_none(), "saturated");
        drop(a);
        assert_eq!(checker.in_flight(), 1);
        let _c = checker.try_begin().expect("a slot freed up");
        drop(b);
        let stats = checker.stats();
        assert_eq!((stats.scheduled, stats.skipped_saturated), (3, 1));
    }

    fn record(verdict: SpotCheckVerdict) -> Arc<SpotCheckRecord> {
        Arc::new(SpotCheckRecord {
            task_id: uuid::Uuid::new_v4(),
            plugin: "0123456789abcdef0123456789abcdef/demo@1.0.0"
                .parse()
                .unwrap(),
            policy: PolicyKind::Deterministic,
            policy_hash: PolicyHash([0; 32]),
            checker: PeerId::from_public_key_bytes(&[1; 32]),
            checker_remote: false,
            accepted_blake3: [0; 32],
            rerun_blake3: None,
            distance: None,
            implicated: Vec::new(),
            penalised: Vec::new(),
            reused_replica: false,
            unavailable: Vec::new(),
            verdict,
        })
    }

    #[test]
    fn the_audit_log_is_bounded_and_verdicts_are_counted() {
        let checker = SpotChecker::new(SpotCheckConfig::default());
        for _ in 0..AUDIT_CAPACITY {
            checker.record(record(SpotCheckVerdict::Confirmed));
        }
        checker.record(record(SpotCheckVerdict::Inconclusive("x".into())));
        let recent = checker.recent();
        assert_eq!(recent.len(), AUDIT_CAPACITY);
        assert_eq!(recent.last().unwrap().verdict.label(), "inconclusive");
        let stats = checker.stats();
        assert_eq!(
            (stats.confirmed, stats.inconclusive),
            (AUDIT_CAPACITY as u64, 1)
        );
    }
}
