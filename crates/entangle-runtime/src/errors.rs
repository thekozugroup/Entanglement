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

    /// No plugin with this id is currently loaded.
    #[error("plugin not loaded: {0}")]
    NotLoaded(PluginId),

    /// An I/O error occurred (e.g. reading artifact bytes).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// An integrity-policy check failed (spec §7.5).
    #[error("integrity: {0}")]
    Integrity(#[from] crate::integrity::IntegrityError),
}
