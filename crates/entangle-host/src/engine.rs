//! [`HostEngine`] — shared Wasmtime engine with component-model + async support.

use wasmtime::error::Context as _;
use wasmtime::{Config, Engine};

/// Shared Wasmtime engine configured for WASI 0.2 component-model execution.
///
/// The engine is cheaply cloneable (Arc-backed internally by Wasmtime) and
/// should be shared across all plugin loads within a single broker process.
#[derive(Clone)]
pub struct HostEngine {
    engine: Engine,
}

impl HostEngine {
    /// Create a new [`HostEngine`] with component-model and async support enabled.
    ///
    /// Epoch interruption is enabled so that per-plugin timeouts can be enforced
    /// via a background tokio timer that calls [`Engine::increment_epoch`].
    /// Fuel consumption is disabled in favour of wall-clock timeouts (spec §2).
    pub fn new() -> anyhow::Result<Self> {
        let mut cfg = Config::new();
        cfg.wasm_component_model(true);
        // async_support is deprecated in wasmtime 43 (async is always on); omitted.
        // We cap execution via epoch + tokio timers, not fuel (spec v6 §2).
        cfg.consume_fuel(false);
        cfg.epoch_interruption(true);
        let engine = Engine::new(&cfg).context("create wasmtime engine")?;
        Ok(Self { engine })
    }

    /// Returns a reference to the underlying [`Engine`].
    pub fn engine(&self) -> &Engine {
        &self.engine
    }
}

impl std::fmt::Debug for HostEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostEngine").finish_non_exhaustive()
    }
}
