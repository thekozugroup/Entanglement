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

    /// The operator disabled this plugin id (`[plugins] disabled` in config.toml).
    #[error(
        "ENTANGLE-E0759: plugin {0} is disabled in config.toml ([plugins] disabled); \
         run `entangle plugins enable {0}` to allow it to load again"
    )]
    PluginDisabled(PluginId),

    /// No plugin with this id is currently loaded.
    #[error("plugin not loaded: {0}")]
    NotLoaded(PluginId),

    /// The plugin is loaded but implements the other `entangle:plugin`
    /// world: a one-shot invoke of a stream plugin, or a stream of a
    /// one-shot plugin.
    #[error("plugin {plugin} implements the `{actual}` world, not `{expected}`")]
    WrongWorld {
        /// The plugin that was invoked.
        plugin: PluginId,
        /// The world the call needs (`"plugin"` or `"stream-plugin"`).
        expected: &'static str,
        /// The world the plugin implements.
        actual: &'static str,
    },

    /// An I/O error occurred (e.g. reading artifact bytes).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// An integrity-policy check failed (spec §7.5).
    #[error("integrity: {0}")]
    Integrity(#[from] crate::integrity::IntegrityError),

    /// A native (tier 4–5) plugin could not be sandboxed, staged, or run.
    #[error("native: {0}")]
    Native(#[from] crate::native::NativeError),

    /// A hot reload would widen what the plugin may do and the operator has
    /// not accepted that (spec §4.4.1 case B).
    #[error(
        "ENTANGLE-E0781: reloading {} as {} needs consent: the new version declares more \
         than the loaded one; re-run with --accept-new-capabilities to accept:\n{}",
        .0.from, .0.to, .0.diff
    )]
    ReloadNeedsConsent(Box<crate::kernel::ConsentRequired>),

    /// A hot reload to a lower version, not explicitly allowed.
    #[error(
        "ENTANGLE-E0782: reloading {from} as {to} is a downgrade; re-run with \
         --allow-downgrade to accept"
    )]
    ReloadDowngrade {
        /// The loaded version.
        from: Box<PluginId>,
        /// The lower version offered.
        to: Box<PluginId>,
    },

    /// The new version's `migrate` hook failed: the reload was refused and
    /// the loaded version keeps running.
    #[error("ENTANGLE-E0783: the migrate hook of {to} failed ({message}); {from} keeps running")]
    MigrateFailed {
        /// The version that keeps running.
        from: Box<PluginId>,
        /// The version whose hook failed.
        to: Box<PluginId>,
        /// What the hook (or the host) reported.
        message: String,
    },

    /// Another version of the plugin was loaded, reloaded or unloaded while
    /// this one was being verified: nothing changed (the new version was
    /// rolled back); retry.
    #[error(
        "ENTANGLE-E0789: another version of {0} was loaded or unloaded while this one was \
         being verified; nothing changed, retry"
    )]
    ReloadRaced(Box<PluginId>),

    /// This exact version was replaced by a hot reload, or unloaded, and
    /// calls or streams that started on it are still running: it stays
    /// registered (holding its grants) until they end, so it cannot be
    /// loaded again yet.
    #[error(
        "ENTANGLE-E0790: {0} is still draining: calls or streams that started on it before it \
         was replaced or unloaded are still running; retry once they end"
    )]
    StillDraining(Box<PluginId>),

    /// Host code panicked during this plugin call and the panic was
    /// contained (spec §2.1): the call's instance is discarded, the plugin
    /// stays loaded and the daemon keeps running. See
    /// `entangle_core::fault`.
    #[error(
        "ENTANGLE-E0788: plugin {plugin} call panicked inside the host and was contained \
         (the call failed; the daemon keeps running): {message}"
    )]
    HostPanicked {
        /// The plugin whose call panicked.
        plugin: PluginId,
        /// The panic message.
        message: String,
    },
}
