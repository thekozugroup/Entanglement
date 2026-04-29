//! Convenience logging wrappers over `entangle:plugin/logging`.
//!
//! On non-wasm targets these functions are no-ops (the WIT bindings are not
//! generated for host platforms). On `wasm32-wasip2` they call through to the
//! host logger via the component-model import.

/// Emit a TRACE-level log message to the host.
pub fn trace(_msg: &str) {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::logging::{log, Level};
        log(Level::Trace, _msg);
    }
}

/// Emit a DEBUG-level log message to the host.
pub fn debug(_msg: &str) {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::logging::{log, Level};
        log(Level::Debug, _msg);
    }
}

/// Emit an INFO-level log message to the host.
pub fn info(_msg: &str) {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::logging::{log, Level};
        log(Level::Info, _msg);
    }
}

/// Emit a WARN-level log message to the host.
pub fn warn(_msg: &str) {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::logging::{log, Level};
        log(Level::Warn, _msg);
    }
}

/// Emit an ERROR-level log message to the host.
pub fn error(_msg: &str) {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::logging::{log, Level};
        log(Level::Error, _msg);
    }
}
