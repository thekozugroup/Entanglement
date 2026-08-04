//! [`HostState`] — per-plugin store data carrying WASI context and observability buffers.

use entangle_types::{plugin_id::PluginId, tier::Tier};
use wasmtime::component::ResourceTable;
use wasmtime::{StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

/// Default cap on the size a single guest linear memory may grow to (256 MiB).
pub const DEFAULT_MEMORY_LIMIT_BYTES: usize = 256 * 1024 * 1024;
/// Default cap on the number of elements in a single guest table.
pub const DEFAULT_TABLE_ELEMENTS_LIMIT: usize = 100_000;
/// Default cap on the number of core instances a store may create.
pub const DEFAULT_INSTANCES_LIMIT: usize = 64;
/// Default cap on the number of tables a store may create.
pub const DEFAULT_TABLES_LIMIT: usize = 64;
/// Default cap on the number of linear memories a store may create.
pub const DEFAULT_MEMORIES_LIMIT: usize = 16;

/// Maximum number of log lines retained per invocation (excluding the
/// truncation marker).
pub const MAX_LOG_LINES: usize = 1_000;
/// Maximum total bytes of log message text retained per invocation.
pub const MAX_LOG_BYTES: usize = 256 * 1024;

/// Per-invocation resource caps applied to a plugin's Wasmtime store.
///
/// Converted into a [`wasmtime::StoreLimits`] that is installed via
/// [`Store::limiter`][wasmtime::Store::limiter] before instantiation, so both
/// instantiation-time allocations and runtime `memory.grow` / `table.grow`
/// are bounded.
#[derive(Debug, Clone, Copy)]
pub struct ResourceLimits {
    /// Maximum bytes a single linear memory may grow to.
    pub memory_bytes: usize,
    /// Maximum elements a single table may grow to.
    pub table_elements: usize,
    /// Maximum number of core instances in the store.
    pub instances: usize,
    /// Maximum number of tables in the store.
    pub tables: usize,
    /// Maximum number of linear memories in the store.
    pub memories: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_bytes: DEFAULT_MEMORY_LIMIT_BYTES,
            table_elements: DEFAULT_TABLE_ELEMENTS_LIMIT,
            instances: DEFAULT_INSTANCES_LIMIT,
            tables: DEFAULT_TABLES_LIMIT,
            memories: DEFAULT_MEMORIES_LIMIT,
        }
    }
}

impl ResourceLimits {
    /// Build the [`StoreLimits`] enforcing these caps.
    ///
    /// `trap_on_grow_failure` is enabled so a denied `memory.grow` /
    /// `table.grow` raises a trap the host classifies as
    /// [`HostError::ResourceExhausted`][crate::HostError::ResourceExhausted],
    /// instead of returning `-1` to the guest (which Rust guests turn into an
    /// opaque OOM abort).
    pub(crate) fn to_store_limits(self) -> StoreLimits {
        StoreLimitsBuilder::new()
            .memory_size(self.memory_bytes)
            .table_elements(self.table_elements)
            .instances(self.instances)
            .tables(self.tables)
            .memories(self.memories)
            .trap_on_grow_failure(true)
            .build()
    }
}

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
    /// Each entry is `(level, message)`. Used by tests and observability
    /// hooks. Capped at [`MAX_LOG_LINES`] lines / [`MAX_LOG_BYTES`] bytes —
    /// append via [`HostState::push_log`] so the cap is enforced.
    pub log_buffer: Vec<(String, String)>,
    /// Resource caps for this store; installed via `Store::limiter`.
    pub(crate) limits: StoreLimits,
    /// Total message bytes accumulated in `log_buffer`.
    log_bytes: usize,
    /// Whether the log buffer has been truncated (marker already emitted).
    log_truncated: bool,
    table: ResourceTable,
    wasi: WasiCtx,
}

impl HostState {
    /// Create a new [`HostState`] with a minimal WASI context and the default
    /// [`ResourceLimits`].
    ///
    /// Only stderr is inherited; there are no filesystem preopens, environment
    /// variables, or pre-opened sockets by default.
    pub fn new(plugin_id: PluginId, effective_tier: Tier) -> Self {
        Self::with_limits(plugin_id, effective_tier, ResourceLimits::default())
    }

    /// Create a new [`HostState`] with a minimal WASI context and explicit
    /// per-invocation [`ResourceLimits`].
    pub fn with_limits(plugin_id: PluginId, effective_tier: Tier, limits: ResourceLimits) -> Self {
        let mut builder = WasiCtxBuilder::new();
        // Inherit the host stderr so plugin panics/traps surface in logs.
        // No filesystem, no network preopens — broker will add them per-capability.
        builder.inherit_stderr();
        Self {
            plugin_id,
            effective_tier,
            log_buffer: Vec::new(),
            limits: limits.to_store_limits(),
            log_bytes: 0,
            log_truncated: false,
            table: ResourceTable::new(),
            wasi: builder.build(),
        }
    }

    /// Append a log line, enforcing the [`MAX_LOG_LINES`] / [`MAX_LOG_BYTES`]
    /// caps.
    ///
    /// Once either cap is reached a single truncation marker is appended and
    /// all further lines are dropped, so a misbehaving guest cannot balloon
    /// host memory through the logging import.
    pub fn push_log(&mut self, level: &str, message: String) {
        if self.log_truncated {
            return;
        }
        if self.log_buffer.len() >= MAX_LOG_LINES
            || self.log_bytes.saturating_add(message.len()) > MAX_LOG_BYTES
        {
            self.log_truncated = true;
            self.log_buffer.push((
                "warn".to_string(),
                format!("[log truncated: exceeded {MAX_LOG_LINES} lines or {MAX_LOG_BYTES} bytes]"),
            ));
            return;
        }
        self.log_bytes += message.len();
        self.log_buffer.push((level.to_string(), message));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> HostState {
        let plugin_id: PluginId = "aabbccddeeff00112233445566778899/test-plugin@0.1.0"
            .parse()
            .unwrap();
        HostState::new(plugin_id, Tier::Pure)
    }

    #[test]
    fn push_log_caps_line_count_with_single_marker() {
        let mut state = test_state();
        for i in 0..(MAX_LOG_LINES + 100) {
            state.push_log("info", format!("line {i}"));
        }
        // MAX_LOG_LINES real lines plus exactly one truncation marker.
        assert_eq!(state.log_buffer.len(), MAX_LOG_LINES + 1);
        let (level, msg) = state.log_buffer.last().unwrap();
        assert_eq!(level, "warn");
        assert!(msg.contains("log truncated"), "unexpected marker: {msg}");
        // The marker appears exactly once.
        let markers = state
            .log_buffer
            .iter()
            .filter(|(_, m)| m.contains("log truncated"))
            .count();
        assert_eq!(markers, 1);
    }

    #[test]
    fn push_log_caps_total_bytes_with_single_marker() {
        let mut state = test_state();
        let big = "x".repeat(64 * 1024);
        for _ in 0..10 {
            state.push_log("info", big.clone());
        }
        // 4 lines of 64 KiB fit under the 256 KiB cap; the 5th trips it.
        assert_eq!(state.log_buffer.len(), MAX_LOG_BYTES / (64 * 1024) + 1);
        let (level, msg) = state.log_buffer.last().unwrap();
        assert_eq!(level, "warn");
        assert!(msg.contains("log truncated"), "unexpected marker: {msg}");
    }

    #[test]
    fn push_log_under_caps_is_unchanged() {
        let mut state = test_state();
        state.push_log("info", "hello".to_string());
        state.push_log("error", "world".to_string());
        assert_eq!(
            state.log_buffer,
            vec![
                ("info".to_string(), "hello".to_string()),
                ("error".to_string(), "world".to_string()),
            ]
        );
    }
}
