//! Failure handling for dispatched work (spec §7.1 `retry`, §7.6): what is
//! retried, where a retry goes, and speculative copies of stragglers.
//!
//! # What is retryable — the precise rule
//!
//! A failed attempt is retried only when the failure says nothing about the
//! task itself, i.e. exactly when its [`RetryCause`] is one of:
//!
//! * [`RetryCause::LostAfterSend`] — the transport failed **after the
//!   request was sent and before any answer arrived**
//!   ([`RouteError::Failed`], `ENTANGLE-E0432`): the worker crashed, was
//!   restarted, or the connection to it was lost mid-task;
//! * [`RetryCause::Unreachable`] — the peer was lost: no transport could
//!   connect to it ([`RouteError::Unreachable`], `E0431`), or no transport
//!   knows an address for it any more ([`RouteError::NoRoute`], `E0430`).
//!   Nothing was delivered.
//!
//! Everything else is final and is never retried: an answer from the worker
//! — a plugin error (`Execution`), a plugin that is not loaded, a policy
//! refusal (`PolicyHashMismatch`, `PolicyMutation`), a capability-token
//! refusal (`CapabilityRequired`, `CapabilityRejected`), `NotAuthorized`,
//! `DuplicateTask`, `Internal` —, an integrity failure on the submitter
//! (oversized output, policy-hash mismatch), an answer that could not be
//! decoded, and a **timeout**: a task that did not answer within its own
//! `timeout_ms` (plus the transport overhead) ran into its own limit, and
//! running it again would only run into it again. A transport's own
//! per-request timeout (iroh's or the tailnet's `request_timeout`, 30 s by
//! default; [`RouteError::Failed`] with `timed_out`) is a timeout too, not
//! a lost worker: the worker may still be running the task, so it is never
//! retried (a retry would run the task twice there).
//!
//! Before a retry after [`RetryCause::LostAfterSend`], the attempt that was
//! lost is cancelled on its worker with a `Cancel` control frame (waited
//! for, bounded by [`crate::dispatcher::CANCEL_TIMEOUT`]): only the
//! connection may have been lost, and the worker may still run that copy.
//!
//! # Where a retry goes
//!
//! To a different live worker when one is eligible (resources fit,
//! reputation not `Excluded` for the policy, on a `TrustedExecutor`
//! allowlist when there is one), best placement rank first; never to a
//! worker that already holds a replica of the same replicated task, nor to
//! one this replica already tried. A single-replica task whose worker was
//! lost after the request was sent may go back to the same worker when no
//! other is eligible (it may have restarted) and it still is eligible when
//! the backoff ends; an unreachable worker is never retried. The target is
//! chosen after the backoff, so a worker excluded or removed from the pool
//! meanwhile is not used. Every retry is a new request with a fresh task id and a
//! fresh per-attempt capability token.
//!
//! # Speculative execution
//!
//! See [`SpeculationConfig`]: when a remote attempt runs past a threshold, a
//! backup copy starts on another eligible worker (same rules as a retry);
//! the first **valid** result wins and the other copy is cancelled with a
//! `Cancel` control frame. For a replicated policy a backup only ever
//! replaces the slow replica — it never adds a vote.
//!
//! [`RouteError::Failed`]: crate::transport::RouteError::Failed
//! [`RouteError::Unreachable`]: crate::transport::RouteError::Unreachable
//! [`RouteError::NoRoute`]: crate::transport::RouteError::NoRoute

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use entangle_types::plugin_id::PluginId;
use parking_lot::Mutex;

/// Why a failed attempt may be retried (see the module docs for the rule).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum RetryCause {
    /// The transport failed after the request was sent and before any
    /// answer arrived: the worker crashed or the connection was lost.
    LostAfterSend,
    /// The peer could not be reached at all; nothing was delivered.
    Unreachable,
    /// A stalled stream was preempted to be reassigned (streams only).
    Stalled,
}

impl RetryCause {
    /// Metric label (`entangle_scheduler_retries_total{cause}`).
    pub const fn label(self) -> &'static str {
        match self {
            Self::LostAfterSend => "lost_after_send",
            Self::Unreachable => "unreachable",
            Self::Stalled => "stalled",
        }
    }

    /// Whether a retry may go back to the worker that failed (only when no
    /// other is eligible): only one that may have restarted.
    pub const fn may_return_to_same_worker(self) -> bool {
        matches!(self, Self::LostAfterSend)
    }
}

impl std::fmt::Display for RetryCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// When to start a backup copy of a slow remote attempt (spec §7.6,
/// straggler mitigation). Default: [`SpeculationConfig::Off`].
///
/// Off by default on purpose: a backup is a second execution of the task on
/// another machine — more load on the mesh, and twice the work a
/// non-idempotent plugin does — which an operator should opt into
/// (`[scheduler] speculative`).
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub enum SpeculationConfig {
    /// Never start backups.
    #[default]
    Off,
    /// Start a backup once an attempt has run this long.
    After(Duration),
    /// Start a backup once an attempt has run `factor` times the median
    /// duration of this plugin's successful attempts on this node — but
    /// only once `min_samples` durations are known, and never before
    /// `floor`.
    MedianMultiple {
        /// Multiple of the median, e.g. `2.0`.
        factor: f64,
        /// Durations needed before the median is trusted.
        min_samples: usize,
        /// The earliest a backup may start.
        floor: Duration,
    },
}

impl SpeculationConfig {
    /// The threshold for a `plugin` attempt, if a backup may be started at
    /// all.
    pub fn threshold(&self, plugin: &PluginId, history: &DurationHistory) -> Option<Duration> {
        match *self {
            Self::Off => None,
            Self::After(d) => Some(d),
            Self::MedianMultiple {
                factor,
                min_samples,
                floor,
            } => {
                if !factor.is_finite() || factor <= 0.0 {
                    return None;
                }
                let median = history.median(plugin, min_samples)?;
                // A product too large for a `Duration` (a huge factor) is
                // a threshold that is never reached: no backup.
                let scaled = Duration::try_from_secs_f64(median.as_secs_f64() * factor).ok()?;
                Some(scaled.max(floor))
            }
        }
    }

    /// Whether backups are on.
    pub const fn enabled(&self) -> bool {
        !matches!(self, Self::Off)
    }
}

/// Durations of each plugin's recent successful attempts on this node, for
/// [`SpeculationConfig::MedianMultiple`]. Bounded: at most
/// [`DurationHistory::SAMPLES`] durations per plugin and
/// [`DurationHistory::PLUGINS`] plugins (the oldest plugin entry is
/// forgotten first).
#[derive(Debug, Default)]
pub struct DurationHistory {
    inner: Mutex<HistoryInner>,
}

#[derive(Debug, Default)]
struct HistoryInner {
    per_plugin: HashMap<PluginId, VecDeque<Duration>>,
    order: VecDeque<PluginId>,
}

impl DurationHistory {
    /// Durations kept per plugin.
    pub const SAMPLES: usize = 32;
    /// Plugins tracked.
    pub const PLUGINS: usize = 256;

    /// An empty history.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one successful attempt of `plugin` that took `took`.
    pub fn record(&self, plugin: &PluginId, took: Duration) {
        let mut inner = self.inner.lock();
        if !inner.per_plugin.contains_key(plugin) {
            if inner.order.len() >= Self::PLUGINS {
                if let Some(old) = inner.order.pop_front() {
                    inner.per_plugin.remove(&old);
                }
            }
            inner.order.push_back(plugin.clone());
        }
        let samples = inner.per_plugin.entry(plugin.clone()).or_default();
        if samples.len() >= Self::SAMPLES {
            samples.pop_front();
        }
        samples.push_back(took);
    }

    /// The median of `plugin`'s recorded durations, once at least
    /// `min_samples` (and at least one) are known.
    pub fn median(&self, plugin: &PluginId, min_samples: usize) -> Option<Duration> {
        let inner = self.inner.lock();
        let samples = inner.per_plugin.get(plugin)?;
        if samples.is_empty() || samples.len() < min_samples {
            return None;
        }
        let mut sorted: Vec<Duration> = samples.iter().copied().collect();
        sorted.sort_unstable();
        Some(sorted[sorted.len() / 2])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin(n: u8) -> PluginId {
        format!("0123456789abcdef0123456789abcdef/p{n}@0.1.0")
            .parse()
            .expect("plugin id")
    }

    #[test]
    fn median_needs_enough_samples_and_is_bounded() {
        let h = DurationHistory::new();
        let p = plugin(1);
        assert_eq!(h.median(&p, 1), None);
        for ms in [30, 10, 20] {
            h.record(&p, Duration::from_millis(ms));
        }
        assert_eq!(h.median(&p, 4), None, "three samples are not four");
        assert_eq!(h.median(&p, 3), Some(Duration::from_millis(20)));
        for _ in 0..100 {
            h.record(&p, Duration::from_millis(5));
        }
        assert_eq!(
            h.median(&p, 1),
            Some(Duration::from_millis(5)),
            "only the last {} samples count",
            DurationHistory::SAMPLES
        );
        for n in 0..=DurationHistory::PLUGINS as u16 {
            h.record(
                &format!("0123456789abcdef0123456789abcdef/q{n}@0.1.0")
                    .parse()
                    .expect("id"),
                Duration::from_millis(1),
            );
        }
        assert_eq!(h.median(&p, 1), None, "the oldest plugin was forgotten");
    }

    #[test]
    fn thresholds() {
        let h = DurationHistory::new();
        let p = plugin(2);
        assert_eq!(SpeculationConfig::Off.threshold(&p, &h), None);
        assert_eq!(
            SpeculationConfig::After(Duration::from_millis(250)).threshold(&p, &h),
            Some(Duration::from_millis(250))
        );
        let median = SpeculationConfig::MedianMultiple {
            factor: 3.0,
            min_samples: 2,
            floor: Duration::from_millis(50),
        };
        assert_eq!(median.threshold(&p, &h), None, "no history, no backup");
        h.record(&p, Duration::from_millis(100));
        h.record(&p, Duration::from_millis(100));
        assert_eq!(median.threshold(&p, &h), Some(Duration::from_millis(300)));
        h.record(&p, Duration::from_millis(1));
        h.record(&p, Duration::from_millis(1));
        h.record(&p, Duration::from_millis(1));
        assert_eq!(
            median.threshold(&p, &h),
            Some(Duration::from_millis(50)),
            "never below the floor"
        );
        let nan = SpeculationConfig::MedianMultiple {
            factor: f64::NAN,
            min_samples: 1,
            floor: Duration::ZERO,
        };
        assert_eq!(nan.threshold(&p, &h), None);
    }

    /// A factor so large that the threshold overflows `Duration` means "no
    /// backup", not a panic in the dispatcher.
    #[test]
    fn a_huge_factor_never_panics_and_starts_no_backup() {
        let h = DurationHistory::new();
        let p = plugin(3);
        h.record(&p, Duration::from_secs(10));
        for factor in [1e30, f64::MAX] {
            let c = SpeculationConfig::MedianMultiple {
                factor,
                min_samples: 1,
                floor: Duration::ZERO,
            };
            assert_eq!(c.threshold(&p, &h), None, "factor {factor}");
        }
    }

    #[test]
    fn only_a_lost_worker_may_be_retried_in_place() {
        assert!(RetryCause::LostAfterSend.may_return_to_same_worker());
        assert!(!RetryCause::Unreachable.may_return_to_same_worker());
        assert!(!RetryCause::Stalled.may_return_to_same_worker());
    }
}
