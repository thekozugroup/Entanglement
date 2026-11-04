//! The daemon's standard metric catalogue (spec §9.6).
//!
//! Every metric the daemon records is defined here — name, help text, bucket
//! layout and the *closed* set of label values — so the names operators
//! alert on live in one reviewable place and the recording sites in other
//! crates stay one-liners.
//!
//! # Label cardinality
//!
//! No label ever carries a peer id or free-form text. Each label draws from
//! a closed set, or from a set bounded by construction:
//!
//! | Label | Values |
//! |---|---|
//! | `outcome` | `ok`, `error`, plus the documented per-metric sets |
//! | `class` | `E<d>xx` error-code hundred (at most 100 values), or `none` |
//! | `method` | the RPC method names the daemon implements, else `unknown` |
//! | `capability` | the fixed capability kinds (custom capabilities fold to `custom`) |
//! | `policy` | the five integrity policy kinds |
//! | `tier` | `trusted`, `good`, `probation`, `excluded` |
//! | `state` | the tailnet states / peer states listed per metric |
//! | `plugin` | plugin id, **bounded to [`PLUGIN_LABEL_LIMIT`] distinct ids** per [`PluginLabels`]; further ids fold into `other` |
//!
//! [`Registry`] additionally caps each family at
//! [`MAX_SERIES_PER_FAMILY`](crate::metrics::MAX_SERIES_PER_FAMILY) label
//! sets as a last resort.

use crate::Registry;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::sync::Arc;

/// Latency buckets (seconds) for in-process operations, 100 µs to 60 s.
pub const LATENCY_BUCKETS: &[f64] = &[
    0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
    5.0, 10.0, 30.0, 60.0,
];

/// Latency buckets (seconds) for sub-millisecond crypto checks.
pub const FAST_BUCKETS: &[f64] = &[
    0.00001, 0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.05, 0.25,
];

/// Most distinct plugin ids a [`PluginLabels`] hands out before folding the
/// rest into [`OTHER_PLUGIN`].
pub const PLUGIN_LABEL_LIMIT: usize = 64;

/// The label value plugin ids beyond [`PLUGIN_LABEL_LIMIT`] are folded into.
pub const OTHER_PLUGIN: &str = "other";

/// Metric family names (the operator-facing contract).
pub mod names {
    /// Plugin invocations, by `plugin` and `outcome`.
    pub const PLUGIN_INVOCATIONS: &str = "entangle_plugin_invocations_total";
    /// Plugin invocation wall-clock duration, by `plugin`.
    pub const PLUGIN_DURATION: &str = "entangle_plugin_invocation_duration_seconds";
    /// Failed plugin invocations, by `plugin` and error-code `class`.
    pub const PLUGIN_ERRORS: &str = "entangle_plugin_errors_total";
    /// Currently loaded plugins.
    pub const PLUGINS_LOADED: &str = "entangle_plugins_loaded";
    /// Seconds since each loaded plugin was loaded, by `plugin`.
    pub const PLUGIN_UPTIME: &str = "entangle_plugin_uptime_seconds";
    /// Capability grants, by `capability`.
    pub const CAPABILITY_GRANTS: &str = "entangle_capability_grants_total";
    /// Capability denials, by `capability` and `reason`.
    pub const CAPABILITY_DENIALS: &str = "entangle_capability_denials_total";
    /// Biscuit verification latency, by `outcome`.
    pub const BISCUIT_VERIFY: &str = "entangle_biscuit_verification_seconds";
    /// RPC requests, by `method` and `outcome`.
    pub const RPC_REQUESTS: &str = "entangle_rpc_requests_total";
    /// RPC request handling duration, by `method`.
    pub const RPC_DURATION: &str = "entangle_rpc_request_duration_seconds";
    /// Remote dispatches this node made, by `outcome`.
    pub const REMOTE_DISPATCH: &str = "entangle_remote_dispatch_total";
    /// Remote tasks this node served for peers, by `outcome`.
    pub const REMOTE_SERVE: &str = "entangle_remote_serve_total";
    /// Integrity verdicts, by `policy` and `outcome`.
    pub const INTEGRITY_VERDICTS: &str = "entangle_integrity_verdicts_total";
    /// Replica outputs over `max_output_bytes` (INV-INT-2).
    pub const OUTPUT_SIZE_EXCEEDED: &str = "entangle_integrity_output_size_exceeded_total";
    /// Peers per reputation `tier`, by `policy`.
    pub const REPUTATION_PEERS: &str = "entangle_reputation_peers";
    /// Mesh peers, by `state`.
    pub const MESH_PEERS: &str = "entangle_mesh_peers";
    /// Tasks the dispatcher is executing right now.
    pub const SCHEDULER_INFLIGHT: &str = "entangle_scheduler_inflight_tasks";
    /// Live workers in the scheduler pool.
    pub const SCHEDULER_WORKERS: &str = "entangle_scheduler_workers";
    /// One-hot tailnet liveness, by `state`.
    pub const TAILSCALE_STATE: &str = "entangle_mesh_tailscale_state";
    /// Spans the OTLP exporter dropped because its queue was full.
    pub const OTLP_DROPPED: &str = "entangle_telemetry_spans_dropped_total";
    /// Spans the OTLP exporter delivered.
    pub const OTLP_EXPORTED: &str = "entangle_telemetry_spans_exported_total";
    /// Span batches the OTLP exporter gave up on.
    pub const OTLP_FAILED_BATCHES: &str = "entangle_telemetry_export_failures_total";
}

/// The states `entangle_mesh_tailscale_state` reports; exactly one is `1`.
pub const TAILSCALE_STATES: [&str; 4] = ["active", "stopped", "uninstalled", "unknown"];

/// The RPC methods the daemon implements; anything else is `unknown`.
pub const RPC_METHODS: &[&str] = &[
    "version",
    "time",
    "plugins/list",
    "plugins/load",
    "plugins/unload",
    "plugins/invoke",
    "mesh/peers",
    "mesh/status",
    "compute/dispatch",
    "metrics/export",
    "diag/mesh",
    "security/plan-max-tier",
    "security/apply-max-tier",
    "security/cancel-max-tier",
    "perms/list",
    "perms/revoke",
];

/// A bounded interner for plugin-id label values.
///
/// The first [`PLUGIN_LABEL_LIMIT`] distinct ids get their own label value;
/// later ones are reported as [`OTHER_PLUGIN`]. This is what makes the
/// `plugin` label safe: a daemon that loads thousands of distinct plugin
/// versions over its lifetime still exposes at most 65 values.
#[derive(Clone, Debug, Default)]
pub struct PluginLabels {
    seen: Arc<Mutex<HashSet<String>>>,
}

impl PluginLabels {
    /// An empty interner.
    pub fn new() -> Self {
        Self::default()
    }

    /// The label value to use for plugin `id`.
    pub fn label(&self, id: &str) -> String {
        let mut seen = self.seen.lock();
        if seen.contains(id) {
            return id.to_owned();
        }
        if seen.len() < PLUGIN_LABEL_LIMIT {
            seen.insert(id.to_owned());
            id.to_owned()
        } else {
            OTHER_PLUGIN.to_owned()
        }
    }
}

/// Reduce an error message to its `ENTANGLE-E<dddd>` code *class*: the code's
/// hundred, e.g. `E05xx`. Returns `none` when the message carries no code.
///
/// The first code found wins, so a wrapped error such as
/// `host: ENTANGLE-E0502: trap` classifies as `E05xx`. At most 100 distinct
/// results exist, which keeps `class` labels bounded.
pub fn code_class(message: &str) -> String {
    const PREFIX: &str = "ENTANGLE-E";
    let mut rest = message;
    while let Some(at) = rest.find(PREFIX) {
        let tail = &rest[at + PREFIX.len()..];
        let digits: Vec<u8> = tail.bytes().take(4).collect();
        if digits.len() == 4 && digits.iter().all(u8::is_ascii_digit) {
            return format!("E{}{}xx", digits[0] as char, digits[1] as char);
        }
        rest = tail;
    }
    "none".to_owned()
}

/// A plugin invocation finished.
pub fn plugin_invocation(reg: &Registry, plugin: &str, error: Option<&str>, seconds: f64) {
    let outcome = if error.is_some() { "error" } else { "ok" };
    reg.inc_counter(
        names::PLUGIN_INVOCATIONS,
        "Plugin invocations by plugin and outcome",
        &[("plugin", plugin), ("outcome", outcome)],
        1.0,
    );
    reg.observe_histogram(
        names::PLUGIN_DURATION,
        "Plugin invocation wall-clock duration in seconds",
        &[("plugin", plugin)],
        LATENCY_BUCKETS,
        seconds,
    );
    if let Some(message) = error {
        reg.inc_counter(
            names::PLUGIN_ERRORS,
            "Failed plugin invocations by plugin and error-code class",
            &[("plugin", plugin), ("class", &code_class(message))],
            1.0,
        );
    }
}

/// A capability was granted.
pub fn capability_grant(reg: &Registry, capability: &str) {
    reg.inc_counter(
        names::CAPABILITY_GRANTS,
        "Capability grants by capability kind",
        &[("capability", capability)],
        1.0,
    );
}

/// A capability request was denied.
pub fn capability_denial(reg: &Registry, capability: &str, reason: &str) {
    reg.inc_counter(
        names::CAPABILITY_DENIALS,
        "Capability denials by capability kind and reason",
        &[("capability", capability), ("reason", reason)],
        1.0,
    );
}

/// A biscuit was checked.
pub fn biscuit_verification(reg: &Registry, ok: bool, seconds: f64) {
    reg.observe_histogram(
        names::BISCUIT_VERIFY,
        "Biscuit verification latency in seconds",
        &[("outcome", if ok { "ok" } else { "denied" })],
        FAST_BUCKETS,
        seconds,
    );
}

/// An RPC request was handled. `method` is normalised to the implemented
/// set, so a client cannot mint label values.
pub fn rpc_request(reg: &Registry, method: &str, ok: bool, seconds: f64) {
    let method = if RPC_METHODS.contains(&method) {
        method
    } else {
        "unknown"
    };
    reg.inc_counter(
        names::RPC_REQUESTS,
        "RPC requests by method and outcome",
        &[
            ("method", method),
            ("outcome", if ok { "ok" } else { "error" }),
        ],
        1.0,
    );
    reg.observe_histogram(
        names::RPC_DURATION,
        "RPC request handling duration in seconds",
        &[("method", method)],
        LATENCY_BUCKETS,
        seconds,
    );
}

/// A remote dispatch this node made finished with `outcome`
/// (`ok`, `transport_error`, `output_too_large`, `rejected_<code>`).
pub fn remote_dispatch(reg: &Registry, outcome: &str) {
    reg.inc_counter(
        names::REMOTE_DISPATCH,
        "Remote task dispatches by outcome",
        &[("outcome", outcome)],
        1.0,
    );
}

/// A task served for a remote peer finished with `outcome`.
pub fn remote_serve(reg: &Registry, outcome: &str) {
    reg.inc_counter(
        names::REMOTE_SERVE,
        "Tasks executed for remote peers by outcome",
        &[("outcome", outcome)],
        1.0,
    );
}

/// An integrity verdict was reached.
pub fn integrity_verdict(reg: &Registry, policy: &str, outcome: &str) {
    reg.inc_counter(
        names::INTEGRITY_VERDICTS,
        "Integrity verdicts by policy kind and outcome",
        &[("policy", policy), ("outcome", outcome)],
        1.0,
    );
}

/// A replica exceeded `max_output_bytes`.
pub fn output_size_exceeded(reg: &Registry) {
    reg.inc_counter(
        names::OUTPUT_SIZE_EXCEEDED,
        "Replica outputs larger than the task's max_output_bytes",
        &[],
        1.0,
    );
}

/// Set the one-hot tailnet state gauge. `active` is one of
/// [`TAILSCALE_STATES`]; every other state is set to 0.
///
/// All four samples change in one step, so a concurrent scrape sees the old
/// state or the new one, never two states at 1 or none.
pub fn tailscale_state(reg: &Registry, active: &str) {
    let labels = TAILSCALE_STATES.map(|state| [("state", state)]);
    let samples: Vec<(&[(&str, &str)], f64)> = labels
        .iter()
        .zip(TAILSCALE_STATES)
        .map(|(l, state)| (&l[..], if state == active { 1.0 } else { 0.0 }))
        .collect();
    reg.set_gauges(
        names::TAILSCALE_STATE,
        "Tailnet liveness state (1 for the current state)",
        &samples,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_class_reduces_to_the_hundred() {
        assert_eq!(code_class("ENTANGLE-E0502: trap"), "E05xx");
        assert_eq!(code_class("host: ENTANGLE-E0301 timed out"), "E03xx");
        assert_eq!(code_class("no code here"), "none");
        // A malformed code is skipped; a later well-formed one is found.
        assert_eq!(code_class("ENTANGLE-Eabc then ENTANGLE-E0900"), "E09xx");
        assert_eq!(code_class("ENTANGLE-E12"), "none");
    }

    #[test]
    fn plugin_labels_fold_beyond_the_limit() {
        let labels = PluginLabels::new();
        for i in 0..PLUGIN_LABEL_LIMIT {
            assert_eq!(labels.label(&format!("p{i}")), format!("p{i}"));
        }
        assert_eq!(labels.label("one-too-many"), OTHER_PLUGIN);
        // Already-seen ids keep their own label.
        assert_eq!(labels.label("p3"), "p3");
    }

    #[test]
    fn rpc_method_label_is_normalised() {
        let r = Registry::new();
        rpc_request(&r, "plugins/list", true, 0.001);
        rpc_request(&r, "evil/\"method\"", false, 0.001);
        assert_eq!(
            r.value(
                names::RPC_REQUESTS,
                &[("method", "unknown"), ("outcome", "error")]
            ),
            Some(1.0)
        );
        assert_eq!(
            r.value(
                names::RPC_REQUESTS,
                &[("method", "plugins/list"), ("outcome", "ok")]
            ),
            Some(1.0)
        );
    }

    #[test]
    fn tailscale_state_is_one_hot() {
        let r = Registry::new();
        tailscale_state(&r, "stopped");
        tailscale_state(&r, "active");
        let sum: f64 = TAILSCALE_STATES
            .iter()
            .map(|s| r.value(names::TAILSCALE_STATE, &[("state", s)]).unwrap())
            .sum();
        assert_eq!(sum, 1.0);
        assert_eq!(
            r.value(names::TAILSCALE_STATE, &[("state", "active")]),
            Some(1.0)
        );
    }

    /// A scrape racing a state change sees the old state or the new one,
    /// never two states at 1 (stopped -> active) or none (active -> stopped).
    #[test]
    fn a_render_racing_a_tailscale_transition_sees_exactly_one_state() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let r = Registry::new();
        tailscale_state(&r, "stopped");
        let stop = Arc::new(AtomicBool::new(false));
        let flipper = {
            let (r, stop) = (r.clone(), stop.clone());
            std::thread::spawn(move || {
                let mut active = false;
                while !stop.load(Ordering::Relaxed) {
                    active = !active;
                    tailscale_state(&r, if active { "active" } else { "stopped" });
                }
            })
        };
        let mut torn = None;
        for _ in 0..20_000 {
            let out = r.render();
            let ones = out
                .lines()
                .filter(|l| l.starts_with(names::TAILSCALE_STATE) && l.ends_with(" 1"))
                .count();
            if ones != 1 {
                torn = Some((ones, out));
                break;
            }
        }
        stop.store(true, Ordering::Relaxed);
        flipper.join().unwrap();
        if let Some((ones, out)) = torn {
            panic!("a render saw {ones} states at 1:\n{out}");
        }
    }
}
