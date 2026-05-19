//! OpenTelemetry exporter scaffold.
//!
//! Phase 2 will wire an OTLP/gRPC exporter against the local OTEL collector
//! (default `localhost:4317`). For Phase 1 this module exposes the public
//! surface so the daemon and operator docs can already mention the env vars
//! and config keys without committing to a concrete implementation.
//!
//! Reasoning: OpenTelemetry's Rust client surface is in active flux and we
//! prefer to wait for the `tracing-opentelemetry` 0.30 line to stabilise
//! before pinning a version into the workspace.

/// Configuration for the OTLP exporter.
#[derive(Clone, Debug)]
pub struct OtelConfig {
    /// OTLP/gRPC endpoint (e.g. `http://localhost:4317`).
    pub endpoint: String,
    /// Logical service name to attach to exported traces & metrics.
    pub service_name: String,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:4317".to_string(),
            service_name: "entangled".to_string(),
        }
    }
}

/// Errors surfaced by the OTEL exporter.
#[derive(Debug, thiserror::Error)]
pub enum OtelError {
    /// The exporter has not yet been implemented (Phase 2).
    #[error("ENTANGLE-E0650: OpenTelemetry exporter not implemented yet (Phase 2)")]
    NotImplemented,
}

/// Initialise the OTEL exporter.
///
/// Phase 1 returns [`OtelError::NotImplemented`] unconditionally; the
/// signature is the Phase-2 contract.
pub fn init(cfg: &OtelConfig) -> Result<(), OtelError> {
    let _ = cfg; // silence dead-code lints for the scaffold
    Err(OtelError::NotImplemented)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_points_at_localhost_otel_collector() {
        let c = OtelConfig::default();
        assert!(c.endpoint.contains("localhost"));
        assert!(c.endpoint.contains(":4317"));
        assert_eq!(c.service_name, "entangled");
    }

    #[test]
    fn init_returns_not_implemented_in_phase_1() {
        let err = init(&OtelConfig::default()).expect_err("Phase 1 must reject init");
        assert!(matches!(err, OtelError::NotImplemented));
        assert!(err.to_string().contains("ENTANGLE-E0650"));
    }
}
