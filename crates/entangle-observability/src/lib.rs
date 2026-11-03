//! Tracing subscriber bootstrap shared by `entangle-cli` and `entangled`.
//!
//! See spec §9.6 — operator DX.
//!
//! - TTY stderr  → compact human-readable format
//! - non-TTY     → newline-delimited JSON (systemd / Docker / log aggregators)
//! - Level filter respects `RUST_LOG`, defaulting to `info,tokio=warn,wasmtime=warn`
//!
//! Beyond the subscriber bootstrap this crate holds the daemon's
//! observability building blocks:
//!
//! - [`metrics`] / [`catalog`]: the Prometheus [`Registry`] and the standard
//!   metric catalogue with its bounded label sets.
//! - [`context`]: W3C `traceparent` parsing/propagation and the span-recording
//!   layer.
//! - `otel` (feature `otlp`, on by default): an OTLP/HTTP JSON trace exporter.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod catalog;
pub mod context;
pub mod metrics;
#[cfg(feature = "otlp")]
pub mod otel;

pub use metrics::Registry;
#[cfg(feature = "otlp")]
pub use otel::{OtelConfig, OtelError, OtelExporter};

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
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_directive));

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

/// Like [`init_with_filter`], additionally exporting spans over OTLP/HTTP when
/// `otel` is `Some`.
///
/// Returns the running exporter (call [`OtelExporter::shutdown`] before the
/// process exits so the last batch is delivered), or `None` when `otel` is
/// `None`. Validation errors (`ENTANGLE-E0651`-`E0654`) are returned before
/// any global state is touched.
///
/// With an exporter the `RUST_LOG` filter applies to the log output only; the
/// exporter has its own filter (spans from `entangle*` targets at `INFO` and
/// above, plus their `WARN`/`ERROR` events), so a quiet console does not blind
/// the trace backend.
///
/// Panics if a global subscriber is already installed.
#[cfg(feature = "otlp")]
pub fn init_with_otel(
    default_directive: &str,
    otel: Option<&OtelConfig>,
) -> Result<Option<OtelExporter>, OtelError> {
    use tracing_subscriber::filter::filter_fn;
    use tracing_subscriber::Layer as _;

    let Some(cfg) = otel else {
        init_with_filter(default_directive);
        return Ok(None);
    };
    let exporter = otel::init(cfg)?;
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_directive));
    let spans = exporter.layer().with_filter(filter_fn(|meta| {
        meta.target().starts_with("entangle") && *meta.level() <= tracing::Level::INFO
    }));
    let registry = tracing_subscriber::registry().with(spans);
    if std::io::stderr().is_terminal() {
        registry
            .with(
                fmt::layer()
                    .with_writer(std::io::stderr)
                    .compact()
                    .with_filter(filter),
            )
            .init();
    } else {
        registry
            .with(
                fmt::layer()
                    .with_writer(std::io::stderr)
                    .json()
                    .with_filter(filter),
            )
            .init();
    }
    Ok(Some(exporter))
}
