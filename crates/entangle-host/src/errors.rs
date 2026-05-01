//! Error types for the entangle-host crate.

/// Errors produced by the Wasmtime host during plugin lifecycle.
///
/// Wasmtime 43 returns `wasmtime::Error` (an alias for `anyhow::Error`) from
/// its APIs. We store that directly so callers can inspect the root cause via
/// standard `anyhow` chaining.
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    /// ENTANGLE-E0500: failed to compile a WebAssembly component from bytes.
    #[error("ENTANGLE-E0500: failed to compile component: {0}")]
    Compile(#[from] wasmtime::Error),

    /// ENTANGLE-E0501: failed to register host imports in the Wasmtime linker.
    #[error("ENTANGLE-E0501: linker setup failed: {0}")]
    LinkerSetup(anyhow::Error),

    /// ENTANGLE-E0502: failed to instantiate a compiled component.
    #[error("ENTANGLE-E0502: instantiation failed: {0}")]
    Instantiate(anyhow::Error),

    /// ENTANGLE-E0503: the plugin trapped during execution.
    #[error("ENTANGLE-E0503: plugin trapped during execution: {0}")]
    Trap(anyhow::Error),

    /// ENTANGLE-E0504: the plugin exceeded the configured wall-clock timeout.
    #[error("ENTANGLE-E0504: timed out after {0}ms")]
    Timeout(u64),

    /// ENTANGLE-E0505: the plugin's `run` export returned an application-level error.
    #[error("ENTANGLE-E0505: plugin returned error: {0}")]
    PluginReturnedError(String),
}
