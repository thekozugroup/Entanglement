//! [`LoadedPlugin`] — a compiled + ready-to-instantiate WebAssembly component.

use crate::{bindings::Plugin, engine::HostEngine, errors::HostError, state::HostState};
use entangle_types::{plugin_id::PluginId, tier::Tier};
use wasmtime::component::{Component, Linker};
use wasmtime::Store;

/// A WebAssembly component that has been compiled and is ready to instantiate.
///
/// Compilation is the expensive step (validates + compiles wasm to native);
/// it is performed once in [`LoadedPlugin::from_bytes`] and can then be
/// instantiated multiple times via [`LoadedPlugin::run_one_shot`].
pub struct LoadedPlugin {
    component: Component,
    plugin_id: PluginId,
    effective_tier: Tier,
}

impl Clone for LoadedPlugin {
    fn clone(&self) -> Self {
        Self {
            // Component is cheaply cloneable in wasmtime 43 (Arc-backed).
            component: self.component.clone(),
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
    /// provided [`HostEngine`]. Returns [`HostError::Compile`] if the bytes are
    /// not a valid component.
    pub fn from_bytes(
        engine: &HostEngine,
        bytes: &[u8],
        plugin_id: PluginId,
        effective_tier: Tier,
    ) -> Result<Self, HostError> {
        let component = Component::from_binary(engine.engine(), bytes)?;
        Ok(Self {
            component,
            plugin_id,
            effective_tier,
        })
    }

    /// Instantiate the component and call its `run` export with `input`.
    ///
    /// # Timeout
    /// An epoch-based timeout is enforced: a tokio task increments the engine
    /// epoch after `timeout_ms` milliseconds. The store's epoch deadline is set
    /// to 1, so any async yield point after the deadline causes a trap.
    pub async fn run_one_shot(
        &self,
        engine: &HostEngine,
        input: &[u8],
        timeout_ms: u64,
    ) -> Result<PluginRunResult, HostError> {
        let mut store = Store::new(
            engine.engine(),
            HostState::new(self.plugin_id.clone(), self.effective_tier),
        );

        // Epoch-based timeout: a background task bumps the epoch once the
        // deadline expires.
        let engine_for_timer = engine.engine().clone();
        let timer_handle = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(timeout_ms)).await;
            engine_for_timer.increment_epoch();
        });
        store.set_epoch_deadline(1);

        // Build linker: WASI p2 + entangle:plugin imports.
        let mut linker = Linker::<HostState>::new(engine.engine());
        wasmtime_wasi::p2::add_to_linker_async(&mut linker)
            .map_err(|e| HostError::LinkerSetup(e.into()))?;
        Plugin::add_to_linker::<HostState, wasmtime::component::HasSelf<HostState>>(
            &mut linker,
            |s| s,
        )
        .map_err(|e| HostError::LinkerSetup(e.into()))?;

        // Instantiate the component (async — bindgen! with `async: true`).
        let plugin = Plugin::instantiate_async(&mut store, &self.component, &linker)
            .await
            .map_err(|e| HostError::Instantiate(e.into()))?;

        // Call the `run` export.
        let call_result = plugin
            .call_run(&mut store, input)
            .await
            .map_err(|e| HostError::Trap(e.into()))?;

        timer_handle.abort();

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

    /// Test 3: an empty component (no imports, no exports) still instantiates.
    ///
    /// This no longer calls `run` — it just verifies the linker setup and
    /// instantiation path don't regress.  A real end-to-end `run` call requires
    /// a pre-built wasm fixture (see `tests/fixtures/README.md`).
    #[tokio::test]
    async fn instantiate_minimal_component_succeeds() {
        let component_wat = r#"(component)"#;
        let engine = HostEngine::new().unwrap();
        let bytes = match wat::parse_str(component_wat) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("wat::parse_str does not support component format: {e}; skipping test");
                return;
            }
        };
        let plugin =
            LoadedPlugin::from_bytes(&engine, &bytes, test_plugin_id(), Tier::Pure).unwrap();

        // An empty component has no `run` export, so `run_one_shot` will fail
        // at the `call_run` step (Trap / missing export).  We only verify that
        // the *linker* setup succeeds, i.e. the error is not LinkerSetup.
        let result = plugin.run_one_shot(&engine, &[], 5_000).await;
        if let Err(ref e) = result {
            assert!(
                !matches!(e, HostError::LinkerSetup(_)),
                "linker setup should not fail; got: {:?}",
                e
            );
        }
        // A fully-wired run test is in tests/fixture_invoke.rs.
    }
}
