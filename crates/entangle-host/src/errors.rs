//! Error types for the entangle-host crate.

/// Errors produced by the Wasmtime host during plugin lifecycle.
///
/// Wasmtime returns `wasmtime::Error` (an alias for `anyhow::Error`) from
/// its APIs. We store that directly so callers can inspect the root cause via
/// standard `anyhow` chaining.
///
/// The stable code block `ENTANGLE-E0500`–`ENTANGLE-E0510` is reserved for this
/// enum; see the range table in `entangle-types::errors` for the workspace map.
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

    /// ENTANGLE-E0506: the store's resource limiter denied an allocation.
    ///
    /// Raised when a plugin exceeds the per-invocation caps configured via
    /// [`ResourceLimits`](crate::state::ResourceLimits) — linear-memory growth,
    /// table growth, or the instance/table/memory count limits — either during
    /// instantiation or mid-execution.
    #[error("ENTANGLE-E0506: resource limit exceeded: {0}")]
    ResourceExhausted(anyhow::Error),

    /// ENTANGLE-E0508: a stream exceeded its negotiated cumulative output budget.
    #[error("ENTANGLE-E0508: stream total {actual} exceeds negotiated {limit} bytes")]
    StreamTotalBytesExceeded {
        /// Negotiated lifetime byte cap.
        limit: u64,
        /// Cumulative bytes including the rejected chunk.
        actual: u64,
    },
    /// ENTANGLE-E0509: a stream produced an empty or oversized chunk.
    #[error("ENTANGLE-E0509: invalid stream chunk size {actual} (limit {limit})")]
    StreamChunkSizeExceeded {
        /// Maximum bytes in one chunk.
        limit: u32,
        /// Actual chunk length.
        actual: u64,
    },

    /// The selected loaded libtest package differs from the submitter's pinned identity.
    #[error("ENTANGLE-E0510: libtest suite identity mismatch")]
    LibtestIdentityMismatch,

    /// ENTANGLE-E0507: the artifact format is incompatible with the declared runtime.
    #[error("ENTANGLE-E0507: declared runtime {declared} but artifact uses {observed} format")]
    RuntimeKindMismatch {
        /// Runtime kind selected by the plugin manifest.
        declared: &'static str,
        /// Format identified from the artifact header.
        observed: &'static str,
    },
}
