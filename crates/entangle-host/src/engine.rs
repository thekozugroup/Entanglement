//! [`HostEngine`] — shared Wasmtime engine with component-model + async support.

use crate::bindings::Plugin;
use crate::state::HostState;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use wasmtime::component::Linker;
use wasmtime::error::Context as _;
use wasmtime::{Config, Engine};

/// Interval, in milliseconds, at which the engine-wide ticker advances the
/// epoch. Per-store deadlines are expressed in ticks of this interval.
pub(crate) const EPOCH_TICK_MS: u64 = 10;

/// Maximum host stack, in bytes, a wasm guest may consume.
///
/// This matches wasmtime's default, but is set explicitly so the cap is
/// auditable and survives upstream default changes. Must stay below
/// wasmtime's `async_stack_size` (2 MiB default).
const MAX_WASM_STACK_BYTES: usize = 512 * 1024;

/// Shared Wasmtime engine configured for WASI 0.2 component-model execution.
///
/// The engine is cheaply cloneable (Arc-backed internally by Wasmtime) and
/// should be shared across all plugin loads within a single broker process.
///
/// Owns two pieces of shared infrastructure:
/// - A pre-built [`Linker`] (WASI p2 + `entangle:plugin` host imports), so
///   linker construction is paid once instead of on every invocation.
/// - A background epoch-ticker thread that increments the engine epoch every
///   [`EPOCH_TICK_MS`]. Each store sets its own absolute epoch deadline, so
///   timeouts are per-invocation and never interfere with one another. The
///   thread holds only an [`Engine::weak`] handle and stops when the last
///   engine handle (or the last `HostEngine` clone) is dropped.
#[derive(Clone)]
pub struct HostEngine {
    engine: Engine,
    linker: Arc<Linker<HostState>>,
    /// Stops the epoch ticker thread when the last clone is dropped.
    _epoch_ticker: Arc<EpochTickerGuard>,
}

/// Drop guard for the epoch ticker thread: sets the stop flag so the thread
/// exits on its next tick.
struct EpochTickerGuard {
    stop: Arc<AtomicBool>,
}

impl Drop for EpochTickerGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl HostEngine {
    /// Create a new [`HostEngine`] with component-model and async support enabled.
    ///
    /// Epoch interruption is enabled so that per-plugin timeouts can be
    /// enforced: a dedicated ticker thread calls [`Engine::increment_epoch`]
    /// every [`EPOCH_TICK_MS`] for the engine's lifetime, and each invocation
    /// sets its own store deadline. Fuel consumption is disabled in favour of
    /// wall-clock timeouts (spec §2).
    pub fn new() -> anyhow::Result<Self> {
        let mut cfg = Config::new();
        cfg.wasm_component_model(true);
        // async_support is deprecated in wasmtime 43 (async is always on); omitted.
        // We cap execution via epoch deadlines + a tokio backstop, not fuel (spec v6 §2).
        cfg.consume_fuel(false);
        cfg.epoch_interruption(true);
        cfg.max_wasm_stack(MAX_WASM_STACK_BYTES);
        let engine = Engine::new(&cfg).context("create wasmtime engine")?;

        // Build the linker once: WASI p2 + entangle:plugin imports. This was
        // previously rebuilt per invocation and dominated invoke latency.
        let mut linker = Linker::<HostState>::new(&engine);
        wasmtime_wasi::p2::add_to_linker_async(&mut linker)
            .context("add WASI p2 imports to linker")?;
        Plugin::add_to_linker::<HostState, wasmtime::component::HasSelf<HostState>>(
            &mut linker,
            |s| s,
        )
        .context("add entangle:plugin host imports to linker")?;

        // Lifetime epoch ticker. Holds only a weak engine handle so it never
        // keeps the engine alive; exits when the last strong handle is gone
        // or when the guard's stop flag is set.
        let stop = Arc::new(AtomicBool::new(false));
        let ticker_stop = Arc::clone(&stop);
        let weak = engine.weak();
        std::thread::Builder::new()
            .name("entangle-epoch-ticker".into())
            .spawn(move || {
                while !ticker_stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(EPOCH_TICK_MS));
                    match weak.upgrade() {
                        Some(engine) => engine.increment_epoch(),
                        None => break,
                    }
                }
            })
            .context("spawn epoch ticker thread")?;

        Ok(Self {
            engine,
            linker: Arc::new(linker),
            _epoch_ticker: Arc::new(EpochTickerGuard { stop }),
        })
    }

    /// Returns a reference to the underlying [`Engine`].
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Returns the shared, pre-built linker (WASI p2 + `entangle:plugin`).
    pub(crate) fn linker(&self) -> &Linker<HostState> {
        &self.linker
    }
}

impl std::fmt::Debug for HostEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostEngine").finish_non_exhaustive()
    }
}
