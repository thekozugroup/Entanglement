//! Error types for sandbox engagement and the subprocess supervisor.
//!
//! The stable code block `ENTANGLE-E0700`–`ENTANGLE-E0749` belongs to the
//! native-plugin path: `E0700`–`E0719` sandbox engagement ([`SandboxError`]),
//! `E0720`–`E0739` the supervisor ([`SupervisorError`]), and `E0740`–`E0749`
//! the runtime's native-plugin glue (`entangle_runtime::native::NativeError`).
//! See the range table in `entangle-types::errors`.

use std::path::PathBuf;

/// Errors raised while planning or engaging an OS sandbox.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// ENTANGLE-E0700: no OS-sandbox primitive is available on this host, and
    /// the operator has not opted out (`[security] allow_unsandboxed_native`).
    #[error(
        "ENTANGLE-E0700: refusing to start a native plugin: no OS sandbox primitive is \
         available ({reason}). Fix the host (see `entangle doctor`), or set \
         `[security] allow_unsandboxed_native = true` to run native plugins without one"
    )]
    Unavailable {
        /// Why no primitive could be used.
        reason: String,
    },

    /// ENTANGLE-E0701: the plugin was not granted network access, but the host
    /// offers no mechanism that can take it away (no network namespace, no
    /// seccomp socket filter, no Landlock network rules).
    #[error(
        "ENTANGLE-E0701: refusing to start a native plugin without network access: \
         this host cannot isolate the network ({reason})"
    )]
    NetworkIsolationUnavailable {
        /// What was missing.
        reason: String,
    },

    /// ENTANGLE-E0702: creating the Landlock ruleset failed.
    #[error("ENTANGLE-E0702: landlock ruleset: {0}")]
    Ruleset(std::io::Error),

    /// ENTANGLE-E0703: a filesystem path named by the profile could not be
    /// added to the sandbox allowlist.
    #[error("ENTANGLE-E0703: cannot allow path {path}: {source}")]
    PathRule {
        /// The offending path.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },

    /// ENTANGLE-E0704: the profile is malformed (relative path, interior NUL, …).
    #[error("ENTANGLE-E0704: invalid sandbox profile: {0}")]
    InvalidProfile(String),

    /// ENTANGLE-E0705: this platform has no native-plugin support at all.
    #[error("ENTANGLE-E0705: native plugins are not supported on this platform: {reason}")]
    UnsupportedPlatform {
        /// Why (e.g. native Windows is Phase 5+).
        reason: String,
    },

    /// ENTANGLE-E0706: building the seccomp filter failed.
    #[error("ENTANGLE-E0706: seccomp filter: {0}")]
    Seccomp(String),
}

/// Errors raised by [`crate::supervisor`] while running one invocation.
#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    /// ENTANGLE-E0720: the plugin did not answer within the deadline; its
    /// whole process group was killed.
    #[error("ENTANGLE-E0720: native plugin timed out after {timeout_ms}ms (process group killed)")]
    Timeout {
        /// The deadline that elapsed.
        timeout_ms: u64,
    },

    /// ENTANGLE-E0721: the plugin announced a response larger than the cap.
    /// The body is never read; the process group is killed.
    #[error(
        "ENTANGLE-E0721: native plugin output of {announced} bytes exceeds the \
         {limit}-byte cap (process group killed)"
    )]
    OutputTooLarge {
        /// The configured cap.
        limit: usize,
        /// The size the plugin's frame header claimed.
        announced: u64,
    },

    /// ENTANGLE-E0722: the request is larger than the input cap.
    #[error("ENTANGLE-E0722: input of {actual} bytes exceeds the {limit}-byte cap")]
    InputTooLarge {
        /// The configured cap.
        limit: usize,
        /// The input size.
        actual: usize,
    },

    /// ENTANGLE-E0723: the plugin answered with an `err` frame.
    #[error("ENTANGLE-E0723: plugin returned error: {0}")]
    PluginError(String),

    /// ENTANGLE-E0724: the plugin violated the frame protocol.
    #[error("ENTANGLE-E0724: native plugin protocol violation: {0}")]
    Protocol(String),

    /// ENTANGLE-E0725: the plugin exited (or closed stdout) without answering.
    #[error(
        "ENTANGLE-E0725: native plugin exited without a response ({status}); \
         last stderr: {stderr_tail}"
    )]
    NoResponse {
        /// Exit status, rendered.
        status: String,
        /// The last few stderr lines, for diagnosis.
        stderr_tail: String,
    },

    /// ENTANGLE-E0726: spawning the sandboxed child failed — this includes a
    /// sandbox step that failed *in the child* before `exec` (fail closed).
    #[error("ENTANGLE-E0726: failed to spawn sandboxed plugin: {0}")]
    Spawn(std::io::Error),

    /// ENTANGLE-E0727: I/O on the plugin's pipes failed.
    #[error("ENTANGLE-E0727: native plugin I/O: {0}")]
    Io(std::io::Error),

    /// A sandbox could not be prepared for this invocation.
    #[error(transparent)]
    Sandbox(#[from] SandboxError),
}
