//! [`LoadedPlugin`] — a compiled + ready-to-instantiate WebAssembly component.

use crate::bindings::PluginPre;
use crate::engine::{HostEngine, EPOCH_TICK_MS};
use crate::errors::HostError;
use crate::libtest::{LibtestCapture, LibtestIdentity};
use crate::state::{HostState, ResourceLimits};
use entangle_types::{plugin_id::PluginId, tier::Tier};
use std::sync::Arc;
use std::time::Duration;
use wasmtime::component::{Component, Linker};
use wasmtime::{Store, Trap};
use wasmtime_wasi::{p2::bindings::CommandPre, I32Exit};

/// Extra wall-clock slack, beyond `timeout_ms`, granted to the tokio backstop
/// timeout. The (precise) epoch deadline normally fires first; the backstop
/// only catches guests parked in host futures where no wasm executes and the
/// epoch deadline can never trap.
const TIMEOUT_BACKSTOP_SLACK_MS: u64 = 250;

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
    pre: Exports,
    plugin_id: PluginId,
    effective_tier: Tier,
}

enum World {
    Plugin,
    Libtest(Option<LibtestIdentity>),
}

#[derive(Clone)]
enum Exports {
    Plugin(PluginPre<HostState>),
    Libtest(Arc<LibtestCommand>),
}

// Keep the signed identity with its pre-instantiated command for every clone.
struct LibtestCommand {
    pre: CommandPre<HostState>,
    identity: Option<LibtestIdentity>,
}

impl Clone for LoadedPlugin {
    fn clone(&self) -> Self {
        Self {
            pre: self.pre.clone(),
            plugin_id: self.plugin_id.clone(),
            effective_tier: self.effective_tier,
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
    /// shared linker. ELF artifacts fail with [`HostError::RuntimeKindMismatch`].
    /// Invalid WebAssembly fails with [`HostError::Compile`], and unsatisfied
    /// imports or a missing `run` export fail with [`HostError::Instantiate`].
    pub fn from_bytes(
        engine: &HostEngine,
        bytes: &[u8],
        plugin_id: PluginId,
        effective_tier: Tier,
    ) -> Result<Self, HostError> {
        Self::compile(engine, bytes, plugin_id, effective_tier, World::Plugin)
    }

    /// Compile a standalone pure WASI CLI test component without a signed package identity.
    /// Pinned requests require [`Self::from_verified_libtest`].
    pub fn from_libtest(
        engine: &HostEngine,
        bytes: &[u8],
        plugin_id: PluginId,
    ) -> Result<Self, HostError> {
        Self::compile(engine, bytes, plugin_id, Tier::Pure, World::Libtest(None))
    }

    /// Compile a libtest module with the package identity that the runtime verified.
    /// Its host-authored response carries this identity for the lifetime of this loaded object.
    pub fn from_verified_libtest(
        engine: &HostEngine,
        bytes: &[u8],
        plugin_id: PluginId,
        identity: LibtestIdentity,
    ) -> Result<Self, HostError> {
        Self::compile(
            engine,
            bytes,
            plugin_id,
            Tier::Pure,
            World::Libtest(Some(identity)),
        )
    }

    fn compile(
        engine: &HostEngine,
        bytes: &[u8],
        plugin_id: PluginId,
        effective_tier: Tier,
        world: World,
    ) -> Result<Self, HostError> {
        if bytes.starts_with(b"\x7fELF") {
            return Err(HostError::RuntimeKindMismatch {
                declared: "wasm-component",
                observed: "ELF",
            });
        }
        let component = Component::from_binary(engine.engine(), bytes)?;
        // Resolve imports + validate exports once, at load time. This moves
        // linker work out of the invocation hot path (previously ~29% of
        // invoke latency) and rejects malformed components early.
        let pre = if let World::Libtest(identity) = world {
            let mut linker = Linker::new(engine.engine());
            wasmtime_wasi::p2::add_to_linker_async(&mut linker).map_err(HostError::LinkerSetup)?;
            CommandPre::new(
                linker
                    .instantiate_pre(&component)
                    .map_err(HostError::Instantiate)?,
            )
            .map(|pre| Exports::Libtest(Arc::new(LibtestCommand { pre, identity })))
        } else {
            PluginPre::new(
                engine
                    .linker()
                    .instantiate_pre(&component)
                    .map_err(HostError::Instantiate)?,
            )
            .map(Exports::Plugin)
        }
        .map_err(HostError::Instantiate)?;
        Ok(Self {
            pre,
            plugin_id,
            effective_tier,
        })
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
        let mut state = HostState::with_limits(self.plugin_id.clone(), self.effective_tier, limits);
        let capture = match &self.pre {
            Exports::Libtest(command) => Some(LibtestCapture::start(
                input,
                &mut state,
                command.identity.as_ref(),
            )?),
            Exports::Plugin(_) => None,
        };
        let mut store = Store::new(engine.engine(), state);
        // Enforce memory/table/instance caps on everything this store
        // allocates, including instantiation-time initial memories.
        store.limiter(|s| &mut s.limits);
        // Independent per-store deadline against the shared engine epoch.
        store.set_epoch_deadline(timeout_ms.div_ceil(EPOCH_TICK_MS).max(1));

        let invoke = async {
            match &self.pre {
                Exports::Plugin(pre) => {
                    let plugin = pre
                        .instantiate_async(&mut store)
                        .await
                        .map_err(|e| classify_instantiate_error(e, timeout_ms))?;
                    plugin
                        .call_run(&mut store, input)
                        .await
                        .map_err(|e| classify_call_error(e, timeout_ms))?
                        .map_err(plugin_error)
                }
                Exports::Libtest(suite) => {
                    let command = suite
                        .pre
                        .instantiate_async(&mut store)
                        .await
                        .map_err(|e| classify_instantiate_error(e, timeout_ms))?;
                    let exit_code = match command.wasi_cli_run().call_run(&mut store).await {
                        Ok(Ok(())) => Some(0),
                        Ok(Err(())) => Some(1),
                        Err(error) => match error.downcast_ref::<I32Exit>() {
                            Some(exit) => Some(exit.0),
                            None if error.downcast_ref::<Trap>()
                                == Some(&Trap::UnreachableCodeReached) =>
                            {
                                None
                            }
                            None => return Err(classify_call_error(error, timeout_ms)),
                        },
                    };
                    capture
                        .expect("WASI command has output capture")
                        .result(exit_code, suite.identity.as_ref())
                }
            }
        };

        let backstop = Duration::from_millis(timeout_ms.saturating_add(TIMEOUT_BACKSTOP_SLACK_MS));
        let output = match tokio::time::timeout(backstop, invoke).await {
            Ok(result) => result?,
            Err(_elapsed) => return Err(HostError::Timeout(timeout_ms)),
        };

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

fn plugin_error(error: crate::bindings::entangle::plugin::types::PluginError) -> HostError {
    use crate::bindings::entangle::plugin::types::PluginError;
    let message = match error {
        PluginError::InvalidInput(s) => format!("invalid-input: {s}"),
        PluginError::ResourceExhausted(s) => format!("resource-exhausted: {s}"),
        PluginError::CapabilityDenied(s) => format!("capability-denied: {s}"),
        PluginError::Internal(s) => format!("internal: {s}"),
    };
    HostError::PluginReturnedError(message)
}

/// `true` when `err`'s chain shows a denial from the store's resource limiter
/// (memory/table growth, or the instance/table/memory count caps).
///
/// Wasmtime does not expose a typed error for limiter denials, so this matches
/// the message text produced by Wasmtime's `StoreLimits` with
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

/// Classify an error from `call_run`.
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

    #[test]
    fn ordinary_exports_do_not_grow_by_the_libtest_identity() {
        // Allow space for a tag on targets where Rust cannot use a niche.
        assert!(
            std::mem::size_of::<Exports>()
                <= std::mem::size_of::<PluginPre<HostState>>()
                    + std::mem::align_of::<PluginPre<HostState>>()
        );
    }

    #[tokio::test]
    async fn standalone_libtest_clones_share_the_command_and_require_a_verified_pin() {
        let bytes = wat::parse_str(
            r#"(component
                (core module $m (func (export "run") (result i32) i32.const 0))
                (core instance $i (instantiate $m))
                (func $run (result (result)) (canon lift (core func $i "run")))
                (instance $command (export "run" (func $run)))
                (export "wasi:cli/run@0.2.0" (instance $command)))"#,
        )
        .unwrap();
        let engine = HostEngine::new().unwrap();
        let plugin = LoadedPlugin::from_libtest(&engine, &bytes, test_plugin_id()).unwrap();
        let cloned = plugin.clone();
        let (Exports::Libtest(first), Exports::Libtest(second)) = (&plugin.pre, &cloned.pre) else {
            panic!("expected WASI commands");
        };
        assert!(Arc::ptr_eq(first, second));
        drop(plugin);

        let output = cloned
            .run_one_shot(&engine, br#"{"operation":"list"}"#, 2000)
            .await
            .unwrap();
        let result: serde_json::Value = serde_json::from_slice(&output.output).unwrap();
        assert_eq!(result["exit_code"], 0);
        assert_eq!(result.get("suite_identity"), Some(&serde_json::Value::Null));

        let pin = LibtestIdentity::from_verified_hashes([1; 32], [2; 32]);
        let request = serde_json::json!({"operation": "list", "expected_suite_identity": pin});
        assert!(matches!(
            cloned
                .run_one_shot(&engine, &serde_json::to_vec(&request).unwrap(), 2000)
                .await,
            Err(HostError::LibtestIdentityMismatch)
        ));
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
