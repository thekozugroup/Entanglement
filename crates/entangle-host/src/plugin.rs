//! [`LoadedPlugin`] — a compiled + ready-to-instantiate WebAssembly component.

use crate::bindings::PluginPre;
use crate::capability::{CapabilityContext, NetLiveness, WasiGrants};
use crate::engine::{HostEngine, EPOCH_TICK_MS};
use crate::errors::HostError;
use crate::state::{HostState, ResourceLimits};
use entangle_types::{plugin_id::PluginId, tier::Tier};
use std::time::{Duration, Instant};
use wasmtime::component::Component;
use wasmtime::{Store, Trap, UpdateDeadline};

/// Extra wall-clock slack, beyond `timeout_ms`, granted to the tokio backstop
/// timeout. The (precise) epoch deadline normally fires first; the backstop
/// only catches guests parked in host futures where no wasm executes and the
/// epoch deadline can never trap.
const TIMEOUT_BACKSTOP_SLACK_MS: u64 = 250;

/// Epoch ticks between the checks a networked instance makes, while it runs
/// wasm code, that its network grants are still live (50 ms).
const REVOCATION_CHECK_TICKS: u64 = 5;

/// A WebAssembly component that has been compiled and is ready to instantiate.
///
/// Compilation and import resolution are the expensive steps (validate +
/// compile wasm to native, then pre-instantiate against the shared linker);
/// both are performed once in [`LoadedPlugin::from_bytes`] and the component
/// can then be instantiated cheaply many times via
/// [`LoadedPlugin::run_one_shot`].
pub struct LoadedPlugin {
    /// Pre-instantiated bindings: imports resolved against the engine's
    /// shared linker and the `run` export validated, at load time.
    pre: PluginPre<HostState>,
    plugin_id: PluginId,
    effective_tier: Tier,
    /// Broker + storage root; `None` = no capabilities at all.
    caps: Option<CapabilityContext>,
}

impl Clone for LoadedPlugin {
    fn clone(&self) -> Self {
        Self {
            // PluginPre is cheaply cloneable in wasmtime 43 (Arc-backed).
            pre: self.pre.clone(),
            plugin_id: self.plugin_id.clone(),
            effective_tier: self.effective_tier,
            caps: self.caps.clone(),
        }
    }
}

/// The outcome of a single plugin invocation.
#[derive(Debug, Clone)]
pub struct PluginRunResult {
    /// Raw bytes returned by the plugin's `run` export.
    pub output: Vec<u8>,
    /// Log lines emitted by the plugin via the `entangle:plugin/logging` host.
    ///
    /// Each entry is `(level, message)`.
    pub log_lines: Vec<(String, String)>,
}

impl LoadedPlugin {
    /// Compile a WebAssembly component from raw bytes.
    ///
    /// This validates the component and compiles it to native code using the
    /// provided [`HostEngine`], then pre-instantiates it against the engine's
    /// shared linker. Returns [`HostError::RuntimeKindMismatch`] if the bytes
    /// are a native executable rather than wasm (ATC-MAN-3),
    /// [`HostError::Compile`] if they are not a valid component, and
    /// [`HostError::Instantiate`] if the component's imports cannot be
    /// satisfied or it lacks the required `run` export.
    pub fn from_bytes(
        engine: &HostEngine,
        bytes: &[u8],
        plugin_id: PluginId,
        effective_tier: Tier,
    ) -> Result<Self, HostError> {
        // A manifest that says "wasm" while shipping an ELF/Mach-O/PE binary
        // is lying about its runtime kind; say so instead of reporting a
        // confusing compile error.
        crate::runtime_kind::check_runtime_kind(crate::runtime_kind::DeclaredRuntime::Wasm, bytes)?;
        let component = Component::from_binary(engine.engine(), bytes)?;
        // Resolve imports + validate exports once, at load time. This moves
        // linker work out of the invocation hot path (previously ~29% of
        // invoke latency) and rejects malformed components early.
        let instance_pre = engine
            .linker()
            .instantiate_pre(&component)
            .map_err(|e| HostError::Instantiate(e.into()))?;
        let pre = PluginPre::new(instance_pre).map_err(|e| HostError::Instantiate(e.into()))?;
        Ok(Self {
            pre,
            plugin_id,
            effective_tier,
            caps: None,
        })
    }

    /// Decide `capability.fetch` through `ctx`'s broker and realise the
    /// plugin's broker grants in every instance's WASI context (see
    /// [`crate::capability`]). Without this, an instance has no preopens, no
    /// network, and every fetch is refused.
    #[must_use]
    pub fn with_capabilities(mut self, ctx: CapabilityContext) -> Self {
        self.caps = Some(ctx);
        self
    }

    /// The capability context, if one is attached.
    pub fn capabilities(&self) -> Option<&CapabilityContext> {
        self.caps.as_ref()
    }

    /// What the plugin's current broker grants realise (creating its storage
    /// directories). The kernel calls this at load so a grant that cannot be
    /// realised fails the load rather than every invocation; each
    /// invocation realises again, so it sees grants as they are then.
    pub async fn realise_capabilities(&self) -> Result<WasiGrants, HostError> {
        match &self.caps {
            Some(ctx) => crate::capability::realise(ctx, &self.plugin_id).await,
            None => Ok(WasiGrants::default()),
        }
    }

    /// Instantiate the component and call its `run` export with `input`,
    /// using the default [`ResourceLimits`].
    ///
    /// See [`LoadedPlugin::run_one_shot_with_limits`] for the timeout and
    /// resource-cap semantics.
    pub async fn run_one_shot(
        &self,
        engine: &HostEngine,
        input: &[u8],
        timeout_ms: u64,
    ) -> Result<PluginRunResult, HostError> {
        self.run_one_shot_with_limits(engine, input, timeout_ms, ResourceLimits::default())
            .await
    }

    /// Instantiate the component and call its `run` export with `input`,
    /// applying explicit per-invocation [`ResourceLimits`].
    ///
    /// # Timeout
    /// Two complementary mechanisms are used:
    /// - **Epoch deadline** (primary): the engine's ticker thread advances the
    ///   epoch every `EPOCH_TICK_MS`; this store gets its own absolute
    ///   deadline of `ceil(timeout_ms / EPOCH_TICK_MS)` ticks, so wasm
    ///   execution traps shortly after `timeout_ms` without affecting any
    ///   concurrent invocation.
    /// - **Tokio backstop**: the whole instantiate + call section is wrapped
    ///   in [`tokio::time::timeout`] with a small slack, catching guests
    ///   parked in WASI host futures where no wasm executes.
    ///
    /// Both paths surface as [`HostError::Timeout`].
    ///
    /// # Capabilities
    /// The instance's WASI context is built from the plugin's broker grants
    /// as they stand now ([`LoadedPlugin::realise_capabilities`]); handles
    /// the guest fetched and did not release are released when the instance
    /// ends.
    ///
    /// # Resource caps
    /// `limits` is enforced via the store's resource limiter; exceeding it
    /// (memory/table growth, or instance/table/memory counts) fails the
    /// invocation with [`HostError::ResourceExhausted`].
    pub async fn run_one_shot_with_limits(
        &self,
        engine: &HostEngine,
        input: &[u8],
        timeout_ms: u64,
        limits: ResourceLimits,
    ) -> Result<PluginRunResult, HostError> {
        let backstop = Duration::from_millis(timeout_ms.saturating_add(TIMEOUT_BACKSTOP_SLACK_MS));
        // Resolving the net.wan allowlist may take at most half the
        // invocation: a slow resolver leaves names unreachable rather than
        // using up the budget and surfacing as a plugin timeout.
        let dns_budget = Duration::from_millis(timeout_ms / 2);
        let realise = async {
            match &self.caps {
                Some(ctx) => {
                    crate::capability::realise_within(ctx, &self.plugin_id, dns_budget).await
                }
                None => Ok(WasiGrants::default()),
            }
        };
        let grants = match tokio::time::timeout(backstop, realise).await {
            Ok(grants) => grants?,
            Err(_elapsed) => return Err(HostError::Timeout(timeout_ms)),
        };
        let state = HostState::with_capabilities(
            self.plugin_id.clone(),
            self.effective_tier,
            limits,
            &grants,
            self.caps.clone(),
        )?;
        // The grants behind the instance's network access, if it has any:
        // their withdrawal stops the invocation (see `crate::capability`).
        let watch = self
            .caps
            .as_ref()
            .map(|ctx| NetLiveness::new(ctx, &self.plugin_id, &grants))
            .filter(NetLiveness::has_net);
        let mut store = Store::new(engine.engine(), state);
        // Enforce memory/table/instance caps on everything this store
        // allocates, including instantiation-time initial memories.
        store.limiter(|s| &mut s.limits);
        // Independent per-store deadline against the shared engine epoch.
        let ticks = timeout_ms.div_ceil(EPOCH_TICK_MS).max(1);
        match &watch {
            None => store.set_epoch_deadline(ticks),
            Some(watch) => {
                // A networked instance stops at its deadline as before, and
                // also as soon as its network grants are withdrawn while it
                // runs wasm code: check every few ticks.
                let watch = watch.clone();
                let deadline = Instant::now() + Duration::from_millis(timeout_ms);
                let step = REVOCATION_CHECK_TICKS.min(ticks);
                store.set_epoch_deadline(step);
                store.epoch_deadline_callback(move |_| {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if watch.withdrawn().is_some() || left.is_zero() {
                        return Ok(UpdateDeadline::Interrupt);
                    }
                    let left_ms = u64::try_from(left.as_millis()).unwrap_or(u64::MAX);
                    Ok(UpdateDeadline::Continue(
                        step.min(left_ms.div_ceil(EPOCH_TICK_MS).max(1)),
                    ))
                });
            }
        }

        let invoke = async {
            // Instantiate the pre-linked component (async — bindgen! with
            // `async: true`).
            let plugin = self
                .pre
                .instantiate_async(&mut store)
                .await
                .map_err(|e| classify_instantiate_error(e.into(), timeout_ms))?;

            // Call the `run` export.
            plugin
                .call_run(&mut store, input)
                .await
                .map_err(|e| classify_call_error(e.into(), timeout_ms))
        };

        let call = tokio::time::timeout(backstop, invoke);
        let outcome = match &watch {
            None => call.await,
            // While the guest waits on the host (a socket read, a poll), the
            // epoch callback cannot run: watch the grants alongside.
            Some(watch) => tokio::select! {
                outcome = call => outcome,
                capability = watch.wait_withdrawn() => {
                    return Err(HostError::CapabilityRevoked {
                        capability: capability.to_owned(),
                    });
                }
            },
        };
        let call_result = match outcome {
            Ok(Ok(result)) => result,
            // The epoch callback interrupts a busy guest the same way for a
            // timeout and a withdrawal: tell them apart.
            Ok(Err(HostError::Timeout(t))) => {
                return Err(match watch.as_ref().and_then(NetLiveness::withdrawn) {
                    Some(capability) => HostError::CapabilityRevoked {
                        capability: capability.to_owned(),
                    },
                    None => HostError::Timeout(t),
                });
            }
            Ok(Err(e)) => return Err(e),
            Err(_elapsed) => return Err(HostError::Timeout(timeout_ms)),
        };

        // Map inner plugin-error to HostError.
        let output = call_result.map_err(|plugin_err| {
            use crate::bindings::entangle::plugin::types::PluginError;
            let msg = match plugin_err {
                PluginError::InvalidInput(s) => format!("invalid-input: {s}"),
                PluginError::ResourceExhausted(s) => format!("resource-exhausted: {s}"),
                PluginError::CapabilityDenied(s) => format!("capability-denied: {s}"),
                PluginError::Internal(s) => format!("internal: {s}"),
            };
            HostError::PluginReturnedError(msg)
        })?;

        let log_lines = std::mem::take(&mut store.data_mut().log_buffer);
        Ok(PluginRunResult { output, log_lines })
    }

    /// Returns the plugin identifier.
    pub fn plugin_id(&self) -> &PluginId {
        &self.plugin_id
    }

    /// Returns the effective capability tier for this plugin.
    pub fn effective_tier(&self) -> Tier {
        self.effective_tier
    }
}

/// `true` when `err`'s chain shows a denial from the store's resource limiter
/// (memory/table growth, or the instance/table/memory count caps).
///
/// wasmtime does not expose a typed error for limiter denials, so this matches
/// the message text produced by wasmtime 43: `StoreLimits` with
/// `trap_on_grow_failure` ("forcing trap when growing …" / "… growth failure
/// to be a trap"), instantiation-time minimum-size checks ("… exceeds
/// memory/table limits"), and store count caps ("resource limit exceeded: …").
fn is_resource_limit_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        let msg = cause.to_string();
        msg.contains("forcing trap when growing")
            || msg.contains("growth failure to be a trap")
            || msg.contains("exceeds memory limits")
            || msg.contains("exceeds table limits")
            || msg.contains("resource limit exceeded")
    })
}

/// Classify an error from `instantiate_async`.
pub(crate) fn classify_instantiate_error(err: anyhow::Error, timeout_ms: u64) -> HostError {
    if matches!(err.downcast_ref::<Trap>(), Some(Trap::Interrupt)) {
        HostError::Timeout(timeout_ms)
    } else if is_resource_limit_error(&err) {
        HostError::ResourceExhausted(err)
    } else {
        HostError::Instantiate(err)
    }
}

/// Classify an error from a guest export call (`call_run`, metric `compare`).
pub(crate) fn classify_call_error(err: anyhow::Error, timeout_ms: u64) -> HostError {
    if matches!(err.downcast_ref::<Trap>(), Some(Trap::Interrupt)) {
        // Epoch deadline reached — the engine ticker advanced the epoch past
        // this store's per-invocation deadline.
        HostError::Timeout(timeout_ms)
    } else if is_resource_limit_error(&err) {
        HostError::ResourceExhausted(err)
    } else {
        HostError::Trap(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::HostEngine;
    use entangle_types::{plugin_id::PluginId, tier::Tier};

    fn test_plugin_id() -> PluginId {
        "aabbccddeeff00112233445566778899/test-plugin@0.1.0"
            .parse()
            .unwrap()
    }

    /// Test 1: engine creation succeeds with component-model + async config.
    #[test]
    fn engine_creates_ok() {
        assert!(HostEngine::new().is_ok());
    }

    /// Test 2: passing invalid bytes returns HostError::Compile.
    #[test]
    fn compile_invalid_bytes_errors() {
        let engine = HostEngine::new().unwrap();
        let result = LoadedPlugin::from_bytes(&engine, &[0, 0, 0, 0], test_plugin_id(), Tier::Pure);
        assert!(
            matches!(result, Err(HostError::Compile(_))),
            "expected Compile error, got: {:?}",
            result.err()
        );
    }

    /// Test 3: a component without the required `run` export is rejected at
    /// load time.
    ///
    /// Pre-instantiation in `from_bytes` resolves imports against the shared
    /// linker and validates exports, so an empty component (no `run`) fails
    /// with `HostError::Instantiate` before any store is created.
    #[test]
    fn component_missing_run_export_fails_at_load() {
        let engine = HostEngine::new().unwrap();
        let bytes = wat::parse_str("(component)").expect("wat parses empty component");
        let result = LoadedPlugin::from_bytes(&engine, &bytes, test_plugin_id(), Tier::Pure);
        assert!(
            matches!(result, Err(HostError::Instantiate(_))),
            "expected Instantiate error for missing `run` export, got: {:?}",
            result.err()
        );
        // A fully-wired run test is in tests/fixture_invoke.rs.
    }
}
