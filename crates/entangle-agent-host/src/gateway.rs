//! MCP gateway HTTP server (scaffold).
//!
//! Spec §8 commits to a local HTTP server that the agent's MCP client points
//! at. The gateway intercepts every tool call, looks up the routing rule in
//! the audit-policy plugin, and forwards the call into the Entanglement
//! kernel (or to a peer via `entangle/agent/1` ALPN for cross-device A2A).
//!
//! Phase 1 ships only the **configuration adapter** layer (see [`crate::adapters`]).
//! The HTTP server itself is Phase 2 work: this module pins the contract and
//! returns a structured `NotImplemented` error so callers cannot mistake the
//! scaffold for a finished implementation.
//!
//! Reasoning for keeping the scaffold even with no implementation:
//!
//! 1. The type signatures are reviewable now — Phase 2 fills in the body.
//! 2. CLI code can wire `entangle agent gateway start` to this module and
//!    surface a clear error instead of a confusing crash.
//! 3. The tests below pin the public surface so renames or signature
//!    changes are deliberate.

use std::net::SocketAddr;

/// Configuration for the MCP gateway HTTP server.
#[derive(Clone, Debug)]
pub struct GatewayConfig {
    /// Address to bind. Default is loopback on an ephemeral port.
    pub bind: SocketAddr,
    /// Opaque bearer token the agent's MCP client must present.
    ///
    /// Each session generates a fresh token (spec §8.3).
    pub bearer_token: String,
    /// Hard cap on concurrent in-flight tool calls per session.
    pub max_in_flight: usize,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:0".parse().expect("loopback addr parses"),
            bearer_token: String::new(),
            max_in_flight: 16,
        }
    }
}

/// Handle returned from [`Gateway::start`].
///
/// Carries the bound socket address so the caller can splice it into the
/// agent's MCP config. The handle drops when the gateway is stopped.
#[derive(Debug)]
pub struct GatewayHandle {
    /// The address the gateway is bound to (resolved after `0`-port binding).
    pub addr: SocketAddr,
}

/// Errors emitted by the gateway.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    /// The gateway has not been implemented yet (Phase 2).
    ///
    /// The static reason string is suitable for logging; callers should
    /// surface it to the user verbatim.
    #[error("ENTANGLE-E0620: MCP gateway not implemented yet (Phase 2): {0}")]
    NotImplemented(&'static str),
    /// Bind / listen failure.
    #[error("ENTANGLE-E0621: bind {addr}: {source}")]
    Bind {
        /// The address the gateway tried to bind to.
        addr: SocketAddr,
        /// Underlying I/O error.
        source: std::io::Error,
    },
}

/// Local MCP gateway.
///
/// Phase 2 will own a `tokio` HTTP/1.1 server, the audit-policy lookup, the
/// in-flight semaphore, and the kernel client. Phase 1 only exposes the
/// constructor and the start-rejection contract.
#[derive(Debug)]
pub struct Gateway {
    config: GatewayConfig,
}

impl Gateway {
    /// Construct a new gateway with the given config.
    pub const fn new(config: GatewayConfig) -> Self {
        Self { config }
    }

    /// Borrow the active config.
    pub const fn config(&self) -> &GatewayConfig {
        &self.config
    }

    /// Start the gateway.
    ///
    /// Phase 1: returns [`GatewayError::NotImplemented`] unconditionally.
    /// The signature is stable: Phase 2 will return `Ok(GatewayHandle { addr })`
    /// once the underlying server is wired.
    pub async fn start(&self) -> Result<GatewayHandle, GatewayError> {
        let _ = &self.config; // keep the field non-dead for clippy
        Err(GatewayError::NotImplemented(
            "see https://github.com/thekozugroup/Entanglement Phase-2 milestone",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_default_is_loopback_ephemeral() {
        let c = GatewayConfig::default();
        assert!(c.bind.ip().is_loopback(), "default bind must be loopback");
        assert_eq!(c.bind.port(), 0, "default port is 0 (ephemeral)");
        assert!(c.max_in_flight >= 1);
    }

    #[tokio::test]
    async fn start_returns_not_implemented_in_phase_1() {
        let gw = Gateway::new(GatewayConfig::default());
        let err = gw.start().await.expect_err("Phase 1 must reject start");
        assert!(matches!(err, GatewayError::NotImplemented(_)));
        let msg = err.to_string();
        assert!(msg.contains("ENTANGLE-E0620"));
        assert!(msg.contains("Phase 2"));
    }

    #[test]
    fn gateway_holds_its_config() {
        let cfg = GatewayConfig {
            bind: "127.0.0.1:8765".parse().unwrap(),
            bearer_token: "abc".into(),
            max_in_flight: 4,
        };
        let gw = Gateway::new(cfg.clone());
        assert_eq!(gw.config().bind, cfg.bind);
        assert_eq!(gw.config().bearer_token, "abc");
        assert_eq!(gw.config().max_in_flight, 4);
    }
}
