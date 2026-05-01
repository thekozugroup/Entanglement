//! [`HostState`] — per-plugin store data carrying WASI context and observability buffers.

use entangle_types::{plugin_id::PluginId, tier::Tier};
use wasmtime::component::ResourceTable;
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

/// Per-plugin host state stored inside a Wasmtime [`Store`][wasmtime::Store].
///
/// Implements [`WasiView`] so that `wasmtime_wasi::p2::add_to_linker_async`
/// can wire up the WASI 0.2 host implementations.
///
/// The WASI context is intentionally minimal: no filesystem preopens, no
/// environment variables, no network sockets. The capability broker
/// will extend the context per-plugin based on the granted tier and manifest.
pub struct HostState {
    /// The plugin this store belongs to.
    pub plugin_id: PluginId,
    /// The effective capability tier for this plugin invocation.
    pub effective_tier: Tier,
    /// Accumulated log lines emitted by the plugin via the logging stub.
    ///
    /// Each entry is `(level, message)`. Used by tests and observability hooks.
    pub log_buffer: Vec<(String, String)>,
    table: ResourceTable,
    wasi: WasiCtx,
}

impl HostState {
    /// Create a new [`HostState`] with a minimal WASI context.
    ///
    /// Only stderr is inherited; there are no filesystem preopens, environment
    /// variables, or pre-opened sockets by default.
    pub fn new(plugin_id: PluginId, effective_tier: Tier) -> Self {
        let mut builder = WasiCtxBuilder::new();
        // Inherit the host stderr so plugin panics/traps surface in logs.
        // No filesystem, no network preopens — broker will add them per-capability.
        builder.inherit_stderr();
        Self {
            plugin_id,
            effective_tier,
            log_buffer: Vec::new(),
            table: ResourceTable::new(),
            wasi: builder.build(),
        }
    }
}

// wasmtime-wasi 43: WasiView has a single `ctx(&mut self) -> WasiCtxView<'_>`
// method. `ResourceTable` is now embedded inside WasiCtxView alongside WasiCtx.
impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}
