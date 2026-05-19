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
    /// The `endpoint` field could not be parsed as a URL or has the wrong scheme.
    #[error("ENTANGLE-E0651: invalid endpoint {endpoint:?}: {reason}")]
    InvalidEndpoint {
        /// The offending endpoint string.
        endpoint: String,
        /// Operator-facing reason.
        reason: &'static str,
    },
    /// The `service_name` field is empty.
    #[error("ENTANGLE-E0652: service_name must be non-empty")]
    EmptyServiceName,
}

/// Validate an [`OtelConfig`] without starting the exporter.
///
/// Phase 1 callers can already wire this into the daemon's config loader
/// so that misconfiguration is reported at startup, not at the first
/// exported span. Returns `Ok(())` if the config is well-formed.
pub fn validate(cfg: &OtelConfig) -> Result<(), OtelError> {
    if cfg.service_name.trim().is_empty() {
        return Err(OtelError::EmptyServiceName);
    }
    // Endpoint must look like `http://...` or `https://...` and have a host.
    let lower = cfg.endpoint.to_ascii_lowercase();
    let rest = if let Some(r) = lower.strip_prefix("http://") {
        r
    } else if let Some(r) = lower.strip_prefix("https://") {
        r
    } else {
        return Err(OtelError::InvalidEndpoint {
            endpoint: cfg.endpoint.clone(),
            reason: "endpoint must start with http:// or https://",
        });
    };
    let host_part = rest.split('/').next().unwrap_or("");
    let host = host_part.split(':').next().unwrap_or("");
    if host.is_empty() {
        return Err(OtelError::InvalidEndpoint {
            endpoint: cfg.endpoint.clone(),
            reason: "endpoint host is empty",
        });
    }
    Ok(())
}

/// Initialise the OTEL exporter.
///
/// Phase 1: validates the config first; on success returns
/// [`OtelError::NotImplemented`]. The signature is the Phase-2 contract.
pub fn init(cfg: &OtelConfig) -> Result<(), OtelError> {
    validate(cfg)?;
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

    #[test]
    fn validate_accepts_default_config() {
        validate(&OtelConfig::default()).expect("default must validate");
    }

    #[test]
    fn validate_rejects_non_http_scheme() {
        let cfg = OtelConfig {
            endpoint: "grpc://localhost:4317".into(),
            service_name: "x".into(),
        };
        let err = validate(&cfg).expect_err("non-http scheme must error");
        match err {
            OtelError::InvalidEndpoint { reason, .. } => {
                assert!(reason.contains("http://"), "got reason: {reason}");
            }
            other => panic!("expected InvalidEndpoint, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_empty_host() {
        let cfg = OtelConfig {
            endpoint: "http:///some/path".into(),
            service_name: "x".into(),
        };
        let err = validate(&cfg).expect_err("empty host must error");
        assert!(matches!(err, OtelError::InvalidEndpoint { .. }));
        assert!(err.to_string().contains("ENTANGLE-E0651"));
    }

    #[test]
    fn validate_rejects_empty_service_name() {
        let cfg = OtelConfig {
            endpoint: "http://localhost:4317".into(),
            service_name: "  ".into(),
        };
        let err = validate(&cfg).expect_err("empty service_name must error");
        assert!(matches!(err, OtelError::EmptyServiceName));
    }

    #[test]
    fn init_propagates_validation_error_before_not_implemented() {
        let cfg = OtelConfig {
            endpoint: "ftp://nope".into(),
            service_name: "x".into(),
        };
        let err = init(&cfg).expect_err("init must reject malformed config");
        // We get InvalidEndpoint, NOT NotImplemented — validation is first.
        assert!(matches!(err, OtelError::InvalidEndpoint { .. }));
    }
}
