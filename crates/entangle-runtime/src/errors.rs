//! Error types for entangle-runtime.

use entangle_types::plugin_id::PluginId;

/// Top-level error type for runtime operations.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// Manifest could not be loaded from disk.
    #[error("manifest: {0}")]
    Manifest(#[from] entangle_manifest::loader::LoadError),

    /// Manifest failed semantic validation.
    #[error("manifest validation: {0}")]
    ManifestValidate(#[from] entangle_manifest::ValidationError),

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
}
