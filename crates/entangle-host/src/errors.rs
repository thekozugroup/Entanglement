//! Error types for the entangle-host crate.

/// Errors produced by the Wasmtime host during plugin lifecycle.
///
/// Wasmtime 43 returns `wasmtime::Error` (an alias for `anyhow::Error`) from
/// its APIs. We store that directly so callers can inspect the root cause via
/// standard `anyhow` chaining.
///
/// The stable code blocks `ENTANGLE-E0500`–`ENTANGLE-E0506` (Wasm execution)
/// and `ENTANGLE-E0507`–`ENTANGLE-E0519` (artifact checks) are reserved for
/// this enum; see the range table in `entangle-types::errors` for the
/// workspace map.
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

    /// ENTANGLE-E0507: the artifact is not the runtime kind its manifest
    /// declares — e.g. `runtime = "wasm"` shipping an ELF executable, or
    /// `runtime = "native"` shipping a wasm component (spec §4.4.1 case C,
    /// ATC-MAN-3).
    #[error(
        "ENTANGLE-E0507: runtime kind mismatch: manifest declares runtime \"{declared}\" \
         but the artifact is {observed}"
    )]
    RuntimeKindMismatch {
        /// What `[plugin] runtime` declares.
        declared: crate::runtime_kind::DeclaredRuntime,
        /// What the artifact's magic bytes say.
        observed: crate::runtime_kind::ArtifactKind,
    },
}
