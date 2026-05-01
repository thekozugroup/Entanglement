/// Errors produced by [`crate::PeerStore`] operations.
#[derive(Debug, thiserror::Error)]
pub enum PeerStoreError {
    /// An I/O error occurred reading or writing the on-disk TOML file.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The on-disk TOML could not be parsed.
    #[error("toml parse: {0}")]
    Parse(#[from] toml::de::Error),
    /// Failed to serialize the store to TOML.
    #[error("toml serialize: {0}")]
    Serialize(#[from] toml::ser::Error),
    /// Requested peer was not found in the store.
    #[error("peer not found: {0}")]
    NotFound(String),
    /// A hex string was malformed.
    #[error("invalid hex: {0}")]
    Hex(String),
}
