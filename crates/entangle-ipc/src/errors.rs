//! Error types for the IPC bus.

/// Errors produced by the in-process message bus.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    /// The topic string is not valid (empty or contains illegal characters).
    #[error("invalid topic: {0}")]
    InvalidTopic(String),

    /// A publish call found no active subscribers; the envelope was dropped.
    #[error("no subscribers — publish dropped")]
    NoSubscribers,

    /// The bus has been dropped; no further messages will arrive.
    #[error("bus closed")]
    Closed,

    /// The subscriber fell too far behind and dropped messages.
    #[error("subscriber lagged: dropped {0} messages")]
    Lagged(u64),
}
