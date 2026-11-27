//! Error types for entangle-runtime.

use entangle_types::plugin_id::PluginId;

/// Top-level error type for runtime operations.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// The lifecycle event bus requires a positive, representable channel capacity.
    #[error("invalid runtime.bus_capacity: {0}")]
    InvalidBusCapacity(usize),

    /// Manifest could not be loaded from disk.
    #[error("manifest: {0}")]
    Manifest(#[from] entangle_manifest::loader::LoadError),

    /// Manifest failed semantic validation.
    #[error("manifest validation: {0}")]
    ManifestValidate(#[from] entangle_manifest::ValidationError),

    /// The current publisher keyring could not be read or parsed.
    #[error("publisher keyring: {0}")]
    Keyring(#[from] entangle_signing::KeyringError),

    /// Artifact signature verification failed.
    #[error("signature: {0}")]
    Signing(#[from] entangle_signing::VerificationError),

    /// Broker refused to register the plugin (policy or duplicate).
    #[error("broker: {0}")]
    Broker(#[from] entangle_broker::BrokerError),

    /// Host engine failed to compile or prepare the plugin.
    #[error("host: {0}")]
    Host(#[from] entangle_host::HostError),

    /// A plugin with this id is already loaded.
    #[error("plugin already loaded: {0}")]
    AlreadyLoaded(PluginId),

    /// The package needs a signed native subprocess supervisor and an enforced OS sandbox.
    #[error("native plugin '{0}' requires a sandboxed native runner, which is unavailable")]
    NativeUnavailable(PluginId),

    /// The operator disabled this plugin in the runtime configuration.
    #[error("plugin disabled in runtime.disabled_plugins: {0}")]
    Disabled(PluginId),

    /// Active native or plugin work held a drain reservation beyond the operator deadline.
    #[error("active work did not drain within {0:?}; finish or cancel its stream or request, then retry")]
    DrainTimeout(std::time::Duration),

    /// The plugin is draining and cannot accept a new invocation.
    #[error("plugin is draining: {0}")]
    Draining(PluginId),

    /// No plugin with this id is currently loaded.
    #[error("plugin not loaded: {0}")]
    NotLoaded(PluginId),

    /// No loaded comparator is signed by a publisher currently trusted on this submitter.
    #[error("MetricNotInKeyring: {0}")]
    MetricNotInKeyring(PluginId),

    /// A progressive guest exceeded the negotiated lifetime output budget.
    #[error("stream total bytes {actual} exceeds limit {limit}")]
    StreamTotalBytesExceeded {
        /// Maximum total bytes.
        limit: u64,
        /// Cumulative bytes including the rejected chunk.
        actual: u64,
    },
    /// A progressive guest issued an empty or oversized chunk.
    #[error("invalid stream chunk size {actual} (limit {limit})")]
    StreamChunkSizeExceeded {
        /// Maximum chunk size.
        limit: u32,
        /// Size of the rejected chunk.
        actual: u64,
    },

    /// Streaming was requested for a package exposing another ABI.
    #[error("plugin {0} does not export a stream")]
    NotStreamPlugin(PluginId),

    /// A general-purpose invocation was requested for another ABI.
    #[error("plugin {0} does not expose the one-shot run export")]
    NotComputePlugin(PluginId),

    /// An I/O error occurred (e.g. reading artifact bytes).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// An integrity-policy check failed (spec §7.5).
    #[error("integrity: {0}")]
    Integrity(#[from] crate::integrity::IntegrityError),
}

impl RuntimeError {
    /// Whether the trusted libtest adapter refused a pin before instantiating the guest.
    pub fn is_libtest_identity_mismatch(&self) -> bool {
        matches!(
            self,
            Self::Host(entangle_host::HostError::LibtestIdentityMismatch)
        )
    }
}
