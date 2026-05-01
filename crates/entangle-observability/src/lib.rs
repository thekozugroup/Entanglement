//! Tracing subscriber bootstrap shared by `entangle-cli` and `entangled`.
//!
//! See spec §9.6 — operator DX.
//!
//! - TTY stderr  → compact human-readable format
//! - non-TTY     → newline-delimited JSON (systemd / Docker / log aggregators)
//! - Level filter respects `RUST_LOG`, defaulting to `info,tokio=warn,wasmtime=warn`

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use is_terminal::IsTerminal;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Initialise the global tracing subscriber with the default filter
/// (`info,tokio=warn,wasmtime=warn`).
///
/// Panics if called more than once (standard `tracing_subscriber` behaviour).
pub fn init_default() {
    init_with_filter("info,tokio=warn,wasmtime=warn");
}

/// Initialise the global tracing subscriber with a caller-supplied default
/// directive string.  `RUST_LOG` overrides `default_directive` at runtime.
///
/// Panics if called more than once.
pub fn init_with_filter(default_directive: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_directive));

    let subscriber = tracing_subscriber::registry().with(filter);

    if std::io::stderr().is_terminal() {
        subscriber
            .with(fmt::layer().with_writer(std::io::stderr).compact())
            .init();
    } else {
        subscriber
            .with(fmt::layer().with_writer(std::io::stderr).json())
            .init();
    }
}
