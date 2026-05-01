//! Error types for the `mesh.local` discovery layer.

/// Errors that can occur during mDNS discovery.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// An mDNS daemon or protocol error.
    #[error("mdns: {0}")]
    Mdns(String),

    /// A peer announcement contained invalid or missing fields.
    #[error("invalid peer announcement: {0}")]
    InvalidAnnouncement(String),

    /// An underlying I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// [`Discovery::start_announcing`] was called while already running.
    #[error("already running")]
    AlreadyRunning,

    /// [`Discovery::shutdown`] was called while not running.
    #[error("not running")]
    NotRunning,
}
