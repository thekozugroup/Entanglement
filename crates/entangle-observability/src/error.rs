//! Errors of the operator read paths (`entangle logs`, `entangle trace`).
//!
//! Codes `ENTANGLE-E0680`..`E0699` are this crate's range for the in-daemon
//! log and trace stores (see the range table in `entangle-types`).

/// Why an operator log or trace query was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QueryError {
    /// ENTANGLE-E0680: the name is neither a subsystem nor a known plugin.
    #[error(
        "ENTANGLE-E0680: no log source named '{name}'. Subsystems: {subsystems}. \
         Plugins with logs: {plugins}. A plugin is addressed by its full id or its name."
    )]
    UnknownLogSource {
        /// What the caller asked for.
        name: String,
        /// The subsystem names, comma-separated.
        subsystems: String,
        /// Loaded plugins and plugins with buffered logs, comma-separated.
        plugins: String,
    },

    /// ENTANGLE-E0681: a plugin name matches more than one plugin.
    #[error(
        "ENTANGLE-E0681: '{name}' matches several plugins ({matches}); use the full plugin id"
    )]
    AmbiguousPlugin {
        /// What the caller asked for.
        name: String,
        /// The candidate ids, comma-separated.
        matches: String,
    },

    /// ENTANGLE-E0682: a query parameter is invalid.
    #[error("ENTANGLE-E0682: invalid log query: {0}")]
    InvalidQuery(String),

    /// ENTANGLE-E0683: the store holds no spans for the id.
    #[error(
        "ENTANGLE-E0683: no spans recorded for {what} '{id}' on this node. The daemon keeps only \
         the most recent spans, in memory and since it started; work that ran on another node is \
         recorded there"
    )]
    NoSuchTrace {
        /// `task` or `trace`.
        what: &'static str,
        /// The id as given.
        id: String,
    },

    /// ENTANGLE-E0684: the id is neither a task UUID nor a 32-hex trace id.
    #[error("ENTANGLE-E0684: '{0}' is not a task id (UUID) or a trace id (32 hex digits)")]
    InvalidTraceId(String),
}
