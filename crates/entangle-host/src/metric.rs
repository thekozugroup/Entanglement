//! [`LoadedMetric`] — a compiled `entangle:integrity/metric@0.1.0` component.
//!
//! A metric component scores how far apart two replica outputs are, for
//! `IntegrityPolicy::SemanticEquivalent` (spec §7.5). This module only knows
//! how to *run* one; signature verification and the decision of *when* to run
//! one belong to the caller (`entangle-runtime`'s metric registry and the
//! scheduler's acceptance pipeline).
//!
//! # Sandbox
//!
//! Metrics run at tier 2 ([`METRIC_TIER`]) on the shared [`HostEngine`]:
//!
//! * **no filesystem** — the WASI context has no preopened directories;
//! * **no network** — the WASI socket address check denies every address and
//!   name lookup is disabled (wasmtime-wasi defaults, which [`HostState`]
//!   keeps);
//! * **bounded memory** — the store's resource limiter, exactly as for
//!   ordinary plugins ([`ResourceLimits`]);
//! * **bounded time** — the same epoch deadline + tokio backstop as
//!   [`LoadedPlugin::run_one_shot_with_limits`](crate::LoadedPlugin::run_one_shot_with_limits).
//!   The engine runs with fuel metering disabled for every component (spec
//!   §2), so wall-clock time is the CPU bound here too.
//!
//! # Observability: the instantiation counter
//!
//! §16 ATC-INT-1 and ATC-INT-5 are statements about *where and how often* a
//! metric component is instantiated. Every [`LoadedMetric::compare`] call
//! creates a fresh store and instantiates the component exactly once, and
//! records that in two places:
//!
//! * a per-component counter, [`LoadedMetric::instantiations`], shared by all
//!   clones of the same `LoadedMetric`;
//! * a `tracing` event at target [`METRIC_TRACE_TARGET`] carrying the
//!   `owner` label the caller supplied (the submitter's peer id in the
//!   scheduler) and the component's BLAKE3 — so a test, or an operator, can
//!   see which node instantiated which metric.
//!
//! The counter is incremented *before* instantiation is attempted: an
//! instantiation that traps still ran the component's start code, so it
//! counts.

use crate::engine::{HostEngine, EPOCH_TICK_MS};
use crate::errors::HostError;
use crate::plugin::{classify_call_error, classify_instantiate_error};
use crate::state::{HostState, ResourceLimits};
use entangle_types::{plugin_id::PluginId, tier::Tier};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use wasmtime::component::Component;
use wasmtime::Store;

/// Generated host bindings for the `entangle:integrity@0.1.0` `metric-plugin`
/// world.
#[allow(missing_docs)] // generated code
mod bindings {
    wasmtime::component::bindgen!({
        // Relative to this crate's Cargo.toml (crates/entangle-host/).
        path: "../entangle-wit/wit-integrity",
        world: "metric-plugin",
        exports: { default: async },
    });
}

/// The tier every metric component runs at (spec §7.5 Rule 1: "tier 2 — no
/// network, no fs").
pub const METRIC_TIER: Tier = Tier::Sandboxed;

/// `tracing` target of the per-instantiation event.
pub const METRIC_TRACE_TARGET: &str = "entangle::integrity::metric";

/// Default wall-clock budget for one `compare` call (10 s).
pub const DEFAULT_METRIC_TIMEOUT_MS: u64 = 10_000;

/// Extra wall-clock slack for the tokio backstop beyond the epoch deadline;
/// mirrors the plugin path.
const TIMEOUT_BACKSTOP_SLACK_MS: u64 = 250;

/// A compiled, pre-linked metric component, ready to be instantiated once per
/// comparison.
///
/// Cheap to clone; clones share the instantiation counter.
#[derive(Clone)]
pub struct LoadedMetric {
    pre: bindings::MetricPluginPre<HostState>,
    plugin_id: PluginId,
    artifact_hex: Arc<str>,
    owner: Arc<str>,
    instantiations: Arc<AtomicU64>,
}

impl std::fmt::Debug for LoadedMetric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedMetric")
            .field("plugin_id", &self.plugin_id)
            .field("artifact", &self.artifact_hex)
            .field("owner", &self.owner)
            .field("instantiations", &self.instantiations())
            .finish_non_exhaustive()
    }
}

impl LoadedMetric {
    /// Compile `bytes` as a metric component and resolve it against the
    /// engine's shared linker.
    ///
    /// Fails with [`HostError::Compile`] for bytes that are not a component,
    /// and with [`HostError::Instantiate`] for a component that does not
    /// export `entangle:integrity/metric@0.1.0` with the right `compare`
    /// signature, or whose imports the host does not provide. Nothing is
    /// instantiated here, so the counter stays at zero.
    ///
    /// `artifact_blake3` identifies the component in the trace event; `owner`
    /// labels the node doing the instantiating (any string — the scheduler
    /// uses the submitter's peer id).
    pub fn from_bytes(
        engine: &HostEngine,
        bytes: &[u8],
        plugin_id: PluginId,
        artifact_blake3: [u8; 32],
        owner: impl Into<String>,
    ) -> Result<Self, HostError> {
        let component = Component::from_binary(engine.engine(), bytes)?;
        let instance_pre = engine
            .linker()
            .instantiate_pre(&component)
            .map_err(|e| HostError::Instantiate(e.into()))?;
        let pre = bindings::MetricPluginPre::new(instance_pre)
            .map_err(|e| HostError::Instantiate(e.into()))?;
        Ok(Self {
            pre,
            plugin_id,
            artifact_hex: hex_lower(&artifact_blake3).into(),
            owner: owner.into().into(),
            instantiations: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Instantiate the component in a fresh tier-2 store and return
    /// `compare(a, b)`.
    ///
    /// Exactly one instantiation per call. Time and memory are bounded as for
    /// a plugin invocation: an epoch deadline of `timeout_ms` plus a tokio
    /// backstop ([`HostError::Timeout`]), and `limits` on memory/table growth
    /// ([`HostError::ResourceExhausted`]). A trap is [`HostError::Trap`].
    ///
    /// The returned value is whatever the guest computed; checking it against
    /// the metric contract (finite or `+inf`, never negative) is the caller's
    /// job, because only the caller knows what to do about a violation.
    pub async fn compare(
        &self,
        engine: &HostEngine,
        a: &[u8],
        b: &[u8],
        timeout_ms: u64,
        limits: ResourceLimits,
    ) -> Result<f64, HostError> {
        let mut store = Store::new(
            engine.engine(),
            HostState::with_limits(self.plugin_id.clone(), METRIC_TIER, limits),
        );
        store.limiter(|s| &mut s.limits);
        store.set_epoch_deadline(timeout_ms.div_ceil(EPOCH_TICK_MS).max(1));

        let count = self.instantiations.fetch_add(1, Ordering::SeqCst) + 1;
        tracing::debug!(
            target: METRIC_TRACE_TARGET,
            owner = %self.owner,
            metric = %self.plugin_id,
            artifact = %self.artifact_hex,
            count,
            "metric component instantiated"
        );

        let run = async {
            let metric = self
                .pre
                .instantiate_async(&mut store)
                .await
                .map_err(|e| classify_instantiate_error(e.into(), timeout_ms))?;
            metric
                .entangle_integrity_metric()
                .call_compare(&mut store, a, b)
                .await
                .map_err(|e| classify_call_error(e.into(), timeout_ms))
        };

        let backstop = Duration::from_millis(timeout_ms.saturating_add(TIMEOUT_BACKSTOP_SLACK_MS));
        match tokio::time::timeout(backstop, run).await {
            Ok(result) => result,
            Err(_elapsed) => Err(HostError::Timeout(timeout_ms)),
        }
    }

    /// How many times this component (any clone of this `LoadedMetric`) has
    /// been instantiated.
    pub fn instantiations(&self) -> u64 {
        self.instantiations.load(Ordering::SeqCst)
    }

    /// The metric's plugin id.
    pub fn plugin_id(&self) -> &PluginId {
        &self.plugin_id
    }

    /// The owner label carried in trace events.
    pub fn owner(&self) -> &str {
        &self.owner
    }
}

/// Lowercase hex without pulling a hex crate into the host.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String cannot fail.
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metric_id() -> PluginId {
        "aabbccddeeff00112233445566778899/metric-test@0.1.0"
            .parse()
            .unwrap()
    }

    #[test]
    fn invalid_bytes_are_a_compile_error() {
        let engine = HostEngine::new().unwrap();
        let err = LoadedMetric::from_bytes(&engine, b"nope", metric_id(), [0; 32], "t")
            .expect_err("garbage must not compile");
        assert!(matches!(err, HostError::Compile(_)), "{err}");
    }

    /// A component without the metric export is rejected at load time, before
    /// any instantiation.
    #[test]
    fn component_without_metric_export_is_rejected_at_load() {
        let engine = HostEngine::new().unwrap();
        let bytes = wat::parse_str("(component)").unwrap();
        let err = LoadedMetric::from_bytes(&engine, &bytes, metric_id(), [0; 32], "t")
            .expect_err("a component exporting nothing is not a metric");
        assert!(matches!(err, HostError::Instantiate(_)), "{err}");
    }

    /// A hand-written metric component: `compare(a, b) = |len(a) - len(b)|`,
    /// or — selected by `body` — a guest that spins forever / grows memory
    /// forever. The bump allocator grows linear memory on demand so it is a
    /// conforming `cabi_realloc`.
    fn wat_metric(body: &str) -> Vec<u8> {
        let wat = format!(
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
      {body}))
  (core instance $i (instantiate $m))
  (func $compare (param "a" (list u8)) (param "b" (list u8)) (result f64)
    (canon lift (core func $i "compare") (memory $i "memory") (realloc (func $i "cabi_realloc"))))
  (instance $metric (export "compare" (func $compare)))
  (export "entangle:integrity/metric@0.1.0" (instance $metric)))"#
        );
        wat::parse_str(wat).expect("metric WAT must assemble")
    }

    const LEN_DIFF: &str = "(f64.abs (f64.sub (f64.convert_i32_u (local.get $la)) (f64.convert_i32_u (local.get $lb))))";
    const SPIN: &str = "(loop $l (br $l)) (f64.const 0)";
    const GROW: &str = "(loop $l (drop (memory.grow (i32.const 16))) (br $l)) (f64.const 0)";

    #[tokio::test(flavor = "multi_thread")]
    async fn compare_runs_the_guest_and_counts_each_instantiation() {
        let engine = HostEngine::new().unwrap();
        let metric = LoadedMetric::from_bytes(
            &engine,
            &wat_metric(LEN_DIFF),
            metric_id(),
            [1; 32],
            "node-a",
        )
        .unwrap();
        assert_eq!(metric.instantiations(), 0, "loading must not instantiate");

        let d = metric
            .compare(&engine, b"hello", b"hi", 1_000, ResourceLimits::default())
            .await
            .unwrap();
        assert_eq!(d, 3.0);
        assert_eq!(metric.instantiations(), 1);

        // Clones share the counter: it counts the component, not the handle.
        let clone = metric.clone();
        let d = clone
            .compare(
                &engine,
                &[0u8; 70_000],
                b"",
                1_000,
                ResourceLimits::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            d, 70_000.0,
            "large lists must cross the canonical ABI intact"
        );
        assert_eq!(metric.instantiations(), 2);
        assert_eq!(clone.instantiations(), 2);
        assert_eq!(metric.owner(), "node-a");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_spinning_metric_is_stopped_by_the_deadline() {
        let engine = HostEngine::new().unwrap();
        let metric =
            LoadedMetric::from_bytes(&engine, &wat_metric(SPIN), metric_id(), [2; 32], "t")
                .unwrap();
        let err = metric
            .compare(&engine, b"a", b"b", 100, ResourceLimits::default())
            .await
            .expect_err("an infinite loop must time out");
        assert!(matches!(err, HostError::Timeout(100)), "{err}");
        assert_eq!(metric.instantiations(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_metric_cannot_exceed_its_memory_limit() {
        let engine = HostEngine::new().unwrap();
        let metric =
            LoadedMetric::from_bytes(&engine, &wat_metric(GROW), metric_id(), [3; 32], "t")
                .unwrap();
        let limits = ResourceLimits {
            memory_bytes: 4 * 1024 * 1024,
            ..ResourceLimits::default()
        };
        let err = metric
            .compare(&engine, b"a", b"b", 5_000, limits)
            .await
            .expect_err("unbounded growth must be refused");
        assert!(matches!(err, HostError::ResourceExhausted(_)), "{err}");
    }

    #[test]
    fn hex_lower_matches_hex_crate_format() {
        assert_eq!(hex_lower(&[0x00, 0xab, 0x0f]), "00ab0f");
    }
}
