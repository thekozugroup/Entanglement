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
//! | `transport` | [`TRANSPORT_LABELS`]: `local`, `tailscale`, `iroh`, or `none` when no transport was tried |
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

/// Duration buckets (seconds) for streams, 10 ms to the 1 h stream ceiling.
pub const STREAM_BUCKETS: &[f64] = &[
    0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0, 900.0, 1800.0, 3600.0,
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
    /// Failed plugin invocations (one-shot calls and streams), by `plugin`
    /// and error-code `class`.
    pub const PLUGIN_ERRORS: &str = "entangle_plugin_errors_total";
    /// Stream-plugin invocations (one per stream), by `plugin` and
    /// `outcome` (`ok`, `error`, `cancelled`).
    pub const PLUGIN_STREAMS: &str = "entangle_plugin_streams_total";
    /// Stream-plugin invocation wall-clock duration, by `plugin`.
    pub const PLUGIN_STREAM_DURATION: &str = "entangle_plugin_stream_duration_seconds";
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
    /// Remote dispatches this node made, by `outcome` and `transport`.
    pub const REMOTE_DISPATCH: &str = "entangle_remote_dispatch_total";
    /// Remote tasks this node served for peers, by `outcome` and `transport`.
    pub const REMOTE_SERVE: &str = "entangle_remote_serve_total";
    /// Streams this node opened to peers, by `outcome` and `transport`.
    pub const REMOTE_STREAM_OPENS: &str = "entangle_remote_stream_opens_total";
    /// Capability-token checks on requests peers sent this node, by `path`
    /// (`task`, `stream`) and `outcome`
    /// ([`REMOTE_CAPABILITY_OUTCOMES`](super::REMOTE_CAPABILITY_OUTCOMES)).
    pub const REMOTE_CAPABILITY: &str = "entangle_remote_capability_checks_total";
    /// Integrity verdicts, by `policy` and `outcome`.
    pub const INTEGRITY_VERDICTS: &str = "entangle_integrity_verdicts_total";
    /// Replica outputs over `max_output_bytes` (INV-INT-2).
    pub const OUTPUT_SIZE_EXCEEDED: &str = "entangle_integrity_output_size_exceeded_total";
    /// Layer-2 spot-checks of accepted tasks, by `policy` and `outcome`
    /// ([`SPOT_CHECK_OUTCOMES`](super::SPOT_CHECK_OUTCOMES)).
    pub const SPOT_CHECKS: &str = "entangle_integrity_spot_checks_total";
    /// Layer-2 spot-checks running right now.
    pub const SPOT_CHECKS_INFLIGHT: &str = "entangle_integrity_spot_checks_inflight";
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
    /// Component loads answered from the AOT compilation cache.
    pub const AOT_CACHE_HITS: &str = "entangle_aot_cache_hits_total";
    /// Component loads the AOT cache had no entry for (compiled).
    pub const AOT_CACHE_MISSES: &str = "entangle_aot_cache_misses_total";
    /// AOT cache entries refused and deleted, by `reason`.
    pub const AOT_CACHE_REJECTIONS: &str = "entangle_aot_cache_rejections_total";
    /// AOT cache entries removed by garbage collection, by `reason`.
    pub const AOT_CACHE_EVICTIONS: &str = "entangle_aot_cache_evictions_total";
    /// Bytes the AOT cache holds on disk.
    pub const AOT_CACHE_BYTES: &str = "entangle_aot_cache_bytes";
    /// Plugin entries restored from the plugin-state file at startup, by `outcome`.
    pub const PLUGIN_RESTORES: &str = "entangle_plugin_restores_total";
    /// Plugin hot reloads, by `outcome`.
    pub const PLUGIN_RELOADS: &str = "entangle_plugin_reloads_total";
    /// Idle plugin instances torn down after their `idle-timeout-secs`.
    pub const PLUGIN_IDLE_TEARDOWNS: &str = "entangle_plugin_idle_teardowns_total";
}

/// The values of the `transport` label: the three mesh transports, and
/// `none` when no transport was tried (no route).
pub const TRANSPORT_LABELS: [&str; 4] = ["local", "tailscale", "iroh", "none"];

/// The values of the `path` label of
/// [`names::REMOTE_CAPABILITY`]: one-shot tasks and stream opens.
pub const REMOTE_CAPABILITY_PATHS: [&str; 2] = ["task", "stream"];

/// The values of the `outcome` label of [`names::REMOTE_CAPABILITY`]: `ok`
/// (a token verified), `tokenless_accepted` (no token, accepted because
/// `[trust] require_capability_tokens = false`), and one per refusal
/// reason (`entangle_biscuits::templates::TokenError::label`). Anything else
/// folds into `other`.
pub const REMOTE_CAPABILITY_OUTCOMES: [&str; 18] = [
    "ok",
    "tokenless_accepted",
    "build",
    "expired",
    "missing",
    "malformed",
    "bad_signature",
    "wrong_holder",
    "capability_not_granted",
    "expiry_out_of_window",
    "binding_mismatch",
    "bad_nonce",
    "replayed",
    "replay_cache_full",
    "revoked",
    "unexpected_content",
    "restriction_not_met",
    "revocations_unavailable",
];

/// `transport` itself when it is one of [`TRANSPORT_LABELS`], else `none`
/// (keeps the label bounded whatever a caller passes).
fn transport_label(transport: &str) -> &'static str {
    TRANSPORT_LABELS
        .iter()
        .copied()
        .find(|t| *t == transport)
        .unwrap_or("none")
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
    "logs/read",
    "trace/get",
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

/// How a stream-plugin invocation ended: the plugin returned (`Ok`), failed
/// (`Err` with its message), or its stream was torn down before it returned
/// (`Cancelled`: the submitter cancelled, the peer was lost, a size cap or
/// the timeout closed the stream).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamEnd<'a> {
    /// The plugin's `start-stream` returned.
    Ok,
    /// The plugin failed; the error message (its code class is recorded).
    Err(&'a str),
    /// The stream was torn down under the plugin: the invocation was dropped
    /// before it returned, or the plugin failed once its stream had been
    /// closed under it, or it ran out of time.
    Cancelled,
}

/// A stream-plugin invocation ended. Counted in its own families
/// ([`names::PLUGIN_STREAMS`], [`names::PLUGIN_STREAM_DURATION`], whose
/// buckets reach the one-hour stream ceiling) so long streams do not skew
/// the one-shot latency histogram; failures share
/// [`names::PLUGIN_ERRORS`] (a plugin id implements exactly one world, so
/// the `plugin` label already tells them apart).
pub fn plugin_stream(reg: &Registry, plugin: &str, end: StreamEnd<'_>, seconds: f64) {
    let outcome = match end {
        StreamEnd::Ok => "ok",
        StreamEnd::Err(_) => "error",
        StreamEnd::Cancelled => "cancelled",
    };
    reg.inc_counter(
        names::PLUGIN_STREAMS,
        "Stream-plugin invocations by plugin and outcome",
        &[("plugin", plugin), ("outcome", outcome)],
        1.0,
    );
    reg.observe_histogram(
        names::PLUGIN_STREAM_DURATION,
        "Stream-plugin invocation wall-clock duration in seconds",
        &[("plugin", plugin)],
        STREAM_BUCKETS,
        seconds,
    );
    if let StreamEnd::Err(message) = end {
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

/// A remote dispatch this node made over `transport` finished with
/// `outcome` (`ok`, `transport_error`, `output_too_large`,
/// `rejected_<code>`). `transport` is one of [`TRANSPORT_LABELS`].
pub fn remote_dispatch(reg: &Registry, outcome: &str, transport: &str) {
    reg.inc_counter(
        names::REMOTE_DISPATCH,
        "Remote task dispatches by outcome and transport",
        &[
            ("outcome", outcome),
            ("transport", transport_label(transport)),
        ],
        1.0,
    );
}

/// A frame served for a remote peer, which arrived over `transport`,
/// finished with `outcome`.
pub fn remote_serve(reg: &Registry, outcome: &str, transport: &str) {
    reg.inc_counter(
        names::REMOTE_SERVE,
        "Tasks executed for remote peers by outcome and transport",
        &[
            ("outcome", outcome),
            ("transport", transport_label(transport)),
        ],
        1.0,
    );
}

/// A capability token on a request a peer sent over `path` (`task` or
/// `stream`) was checked with `outcome` (see [`REMOTE_CAPABILITY_OUTCOMES`];
/// both labels fold unknown values, so they stay bounded).
pub fn remote_capability(reg: &Registry, path: &str, outcome: &str) {
    let path = REMOTE_CAPABILITY_PATHS
        .iter()
        .copied()
        .find(|p| *p == path)
        .unwrap_or("other");
    let outcome = REMOTE_CAPABILITY_OUTCOMES
        .iter()
        .copied()
        .find(|o| *o == outcome)
        .unwrap_or("other");
    reg.inc_counter(
        names::REMOTE_CAPABILITY,
        "Capability-token checks on requests from peers, by path and outcome",
        &[("path", path), ("outcome", outcome)],
        1.0,
    );
}

/// This node tried to open a stream to a peer: `outcome` is `ok`,
/// `transport_error` or `no_route`; `transport` the transport that carried
/// (or last failed) it.
pub fn remote_stream_open(reg: &Registry, outcome: &str, transport: &str) {
    reg.inc_counter(
        names::REMOTE_STREAM_OPENS,
        "Streams opened to remote peers by outcome and transport",
        &[
            ("outcome", outcome),
            ("transport", transport_label(transport)),
        ],
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

/// The values of the `outcome` label of
/// [`names::SPOT_CHECKS`]: a finished re-run that reproduced the accepted
/// output (`confirmed`) or did not (`mismatch`, an attestation failure), one
/// that produced nothing comparable (`inconclusive`), and a sampled task
/// that was not re-run because the concurrency bound was reached
/// (`skipped_saturated`) or no other executor could run it
/// (`skipped_no_checker`).
pub const SPOT_CHECK_OUTCOMES: [&str; 5] = [
    "confirmed",
    "mismatch",
    "inconclusive",
    "skipped_saturated",
    "skipped_no_checker",
];

/// A Layer-2 spot-check of a `policy` task ended with `outcome` (one of
/// [`SPOT_CHECK_OUTCOMES`]; anything else is filed as `inconclusive`).
pub fn spot_check(reg: &Registry, policy: &str, outcome: &str) {
    let outcome = SPOT_CHECK_OUTCOMES
        .iter()
        .copied()
        .find(|o| *o == outcome)
        .unwrap_or("inconclusive");
    reg.inc_counter(
        names::SPOT_CHECKS,
        "Layer-2 spot-checks of accepted tasks by policy kind and outcome",
        &[("policy", policy), ("outcome", outcome)],
        1.0,
    );
}

/// The values of the `reason` label of [`names::AOT_CACHE_REJECTIONS`]:
/// the entry or its directory had the wrong owner, mode or file type
/// (`permissions`), its sidecar was malformed or did not describe it
/// (`header`), it was written by another Wasmtime version (`version`), its
/// MAC did not verify (`mac`), Wasmtime refused it (`deserialize`), or it
/// could not be read (`io`).
pub const AOT_REJECTION_REASONS: [&str; 6] = [
    "permissions",
    "header",
    "version",
    "mac",
    "deserialize",
    "io",
];

/// The values of the `reason` label of [`names::AOT_CACHE_EVICTIONS`]:
/// unused longer than the configured age (`age`), over the size cap
/// (`size`), or a partial write left behind (`orphan`).
pub const AOT_EVICTION_REASONS: [&str; 3] = ["age", "size", "orphan"];

/// An AOT cache lookup hit (`true`) or missed (`false`).
pub fn aot_cache_lookup(reg: &Registry, hit: bool) {
    if hit {
        reg.inc_counter(
            names::AOT_CACHE_HITS,
            "Component loads answered from the AOT compilation cache",
            &[],
            1.0,
        );
    } else {
        reg.inc_counter(
            names::AOT_CACHE_MISSES,
            "Component loads with no AOT cache entry (compiled)",
            &[],
            1.0,
        );
    }
}

/// An AOT cache entry was rejected (and deleted) for `reason` (one of
/// [`AOT_REJECTION_REASONS`]; anything else is filed as `io`).
pub fn aot_cache_rejection(reg: &Registry, reason: &str) {
    let reason = AOT_REJECTION_REASONS
        .iter()
        .copied()
        .find(|r| *r == reason)
        .unwrap_or("io");
    reg.inc_counter(
        names::AOT_CACHE_REJECTIONS,
        "AOT cache entries refused and deleted, by reason",
        &[("reason", reason)],
        1.0,
    );
}

/// `n` AOT cache entries were evicted for `reason` (one of
/// [`AOT_EVICTION_REASONS`]; anything else is filed as `orphan`).
pub fn aot_cache_evictions(reg: &Registry, reason: &str, n: u64) {
    let reason = AOT_EVICTION_REASONS
        .iter()
        .copied()
        .find(|r| *r == reason)
        .unwrap_or("orphan");
    reg.inc_counter(
        names::AOT_CACHE_EVICTIONS,
        "AOT cache entries removed by garbage collection, by reason",
        &[("reason", reason)],
        n as f64,
    );
}

/// Set the AOT cache size gauge.
pub fn aot_cache_bytes(reg: &Registry, bytes: u64) {
    reg.set_gauge(
        names::AOT_CACHE_BYTES,
        "Bytes the AOT compilation cache holds on disk",
        &[],
        bytes as f64,
    );
}

/// The values of the `outcome` label of [`names::PLUGIN_RESTORES`].
pub const RESTORE_OUTCOMES: [&str; 3] = ["restored", "failed", "disabled"];

/// One plugin-state entry was restored at startup with `outcome` (one of
/// [`RESTORE_OUTCOMES`]; anything else is filed as `failed`).
pub fn plugin_restore(reg: &Registry, outcome: &str) {
    let outcome = RESTORE_OUTCOMES
        .iter()
        .copied()
        .find(|o| *o == outcome)
        .unwrap_or("failed");
    reg.inc_counter(
        names::PLUGIN_RESTORES,
        "Plugin-state entries reloaded at daemon start, by outcome",
        &[("outcome", outcome)],
        1.0,
    );
}

/// The values of the `outcome` label of [`names::PLUGIN_RELOADS`].
pub const RELOAD_OUTCOMES: [&str; 3] = ["swapped", "refused", "migrate_failed"];

/// One hot reload ended with `outcome` (one of [`RELOAD_OUTCOMES`];
/// anything else is filed as `refused`).
pub fn plugin_reload(reg: &Registry, outcome: &str) {
    let outcome = RELOAD_OUTCOMES
        .iter()
        .copied()
        .find(|o| *o == outcome)
        .unwrap_or("refused");
    reg.inc_counter(
        names::PLUGIN_RELOADS,
        "Plugin hot reloads by outcome",
        &[("outcome", outcome)],
        1.0,
    );
}

/// An idle plugin's instance was torn down.
pub fn plugin_idle_teardown(reg: &Registry, plugin: &str) {
    reg.inc_counter(
        names::PLUGIN_IDLE_TEARDOWNS,
        "Idle plugin instances torn down after their idle timeout",
        &[("plugin", plugin)],
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
    fn the_transport_label_is_bounded() {
        let reg = Registry::new();
        remote_dispatch(&reg, "ok", "tailscale");
        remote_dispatch(&reg, "ok", "carrier-pigeon");
        assert_eq!(
            reg.value(
                names::REMOTE_DISPATCH,
                &[("outcome", "ok"), ("transport", "tailscale")]
            ),
            Some(1.0)
        );
        assert_eq!(
            reg.value(
                names::REMOTE_DISPATCH,
                &[("outcome", "ok"), ("transport", "none")]
            ),
            Some(1.0)
        );
    }

    #[test]
    fn the_capability_labels_are_bounded() {
        let reg = Registry::new();
        remote_capability(&reg, "task", "replayed");
        remote_capability(&reg, "stream", "ok");
        remote_capability(&reg, "peer-1234", "anything at all");
        let text = reg.render();
        assert!(text.contains("path=\"task\""), "{text}");
        assert!(text.contains("outcome=\"replayed\""), "{text}");
        assert!(
            text.contains("path=\"other\",outcome=\"other\"")
                || text.contains("outcome=\"other\",path=\"other\""),
            "{text}"
        );
        assert!(!text.contains("peer-1234"));
    }

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
    fn spot_check_outcomes_are_a_closed_set() {
        let r = Registry::new();
        spot_check(&r, "deterministic", "mismatch");
        spot_check(&r, "deterministic", "made-up");
        assert_eq!(
            r.value(
                names::SPOT_CHECKS,
                &[("policy", "deterministic"), ("outcome", "mismatch")]
            ),
            Some(1.0)
        );
        assert_eq!(
            r.value(
                names::SPOT_CHECKS,
                &[("policy", "deterministic"), ("outcome", "inconclusive")]
            ),
            Some(1.0),
            "an unknown outcome folds into inconclusive"
        );
    }

    #[test]
    fn stream_invocations_have_their_own_families() {
        let r = Registry::new();
        plugin_stream(&r, "p", StreamEnd::Ok, 2.0);
        plugin_stream(&r, "p", StreamEnd::Cancelled, 0.5);
        plugin_stream(&r, "p", StreamEnd::Err("ENTANGLE-E0511: revoked"), 0.1);
        for outcome in ["ok", "cancelled", "error"] {
            assert_eq!(
                r.value(
                    names::PLUGIN_STREAMS,
                    &[("plugin", "p"), ("outcome", outcome)]
                ),
                Some(1.0),
                "{outcome}"
            );
        }
        assert_eq!(
            r.value(names::PLUGIN_STREAM_DURATION, &[("plugin", "p")]),
            Some(3.0),
            "three observations"
        );
        assert_eq!(
            r.value(names::PLUGIN_ERRORS, &[("plugin", "p"), ("class", "E05xx")]),
            Some(1.0)
        );
        // The one-shot families are untouched.
        assert_eq!(
            r.value(
                names::PLUGIN_INVOCATIONS,
                &[("plugin", "p"), ("outcome", "ok")]
            ),
            None
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
