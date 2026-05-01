//! Error types for the agent-host crate.

/// Errors produced by config adapters.
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    /// Config file could not be parsed (error detail included).
    #[error("ENTANGLE-E0600: parse: {0}")]
    Parse(String),
    /// A filesystem I/O operation failed.
    #[error("ENTANGLE-E0601: io: {0}")]
    Io(String),
    /// The config file has a layout this adapter does not support.
    #[error("ENTANGLE-E0602: unsupported config layout: {0}")]
    Unsupported(String),
}

/// Errors produced by [`crate::AgentSession`].
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// No adapter is registered for the requested agent name.
    #[error("ENTANGLE-E0610: unknown agent: {0}")]
    UnknownAgent(String),
    /// The underlying adapter returned an error.
    #[error("adapter: {0}")]
    Adapter(#[from] AdapterError),
}
