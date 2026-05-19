//! WAN Iroh-QUIC mesh transport for Entanglement (scaffold).
//!
//! Spec §6.1 names `mesh.iroh` as the WAN-capable transport that uses QUIC
//! over direct UDP, hole-punched UDP, and DERP-relayed TCP. This crate is
//! the scaffold: it declares the public surface and returns
//! [`MeshIrohError::NotImplemented`] until Phase 2 wires `iroh = "0.34.x"`.
//!
//! Keeping the crate (rather than no-op'ing the dependency entirely) means
//! callers of the workspace can already write code against the real type
//! signatures; the only thing they cannot do yet is *start* a transport.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::net::SocketAddr;

use entangle_types::peer_id::PeerId;

/// Configuration for the `mesh.iroh` transport.
#[derive(Clone, Debug)]
pub struct MeshIrohConfig {
    /// Local endpoint to bind. `0` selects an ephemeral port.
    pub bind: SocketAddr,
    /// Whether to enable DERP relay (slows path; fallback when hole-punch fails).
    pub allow_derp_relay: bool,
}

impl Default for MeshIrohConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:0".parse().expect("default bind parses"),
            allow_derp_relay: true,
        }
    }
}

/// Errors emitted by the scaffold.
#[derive(Debug, thiserror::Error)]
pub enum MeshIrohError {
    /// The transport is not yet implemented (Phase 2).
    #[error("ENTANGLE-E0630: mesh.iroh transport not implemented yet (Phase 2)")]
    NotImplemented,
}

/// Lightweight peer descriptor exposed by the scaffold.
///
/// Phase 2 will expand this with iroh `NodeAddr` and direct-address state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrohPeer {
    /// Entanglement peer id (Ed25519 public-key bytes).
    pub peer_id: PeerId,
    /// Last-known reachable address.
    pub addr: SocketAddr,
}

/// Scaffolded transport handle.
#[derive(Debug, Default)]
pub struct MeshIroh {
    config: MeshIrohConfig,
}

impl MeshIroh {
    /// Construct a new transport with the given config.
    pub const fn new(config: MeshIrohConfig) -> Self {
        Self { config }
    }

    /// Borrow the active config.
    pub const fn config(&self) -> &MeshIrohConfig {
        &self.config
    }

    /// Start the transport.
    ///
    /// Phase 1: returns [`MeshIrohError::NotImplemented`].
    pub async fn start(&self) -> Result<(), MeshIrohError> {
        let _ = &self.config; // avoid clippy::needless_unused_self
        Err(MeshIrohError::NotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_binds_wildcard_ephemeral() {
        let c = MeshIrohConfig::default();
        assert_eq!(c.bind.port(), 0);
        assert!(c.allow_derp_relay);
    }

    #[tokio::test]
    async fn start_returns_not_implemented_in_phase_1() {
        let t = MeshIroh::new(MeshIrohConfig::default());
        let err = t.start().await.expect_err("Phase 1 must reject start");
        assert!(matches!(err, MeshIrohError::NotImplemented));
        assert!(err.to_string().contains("ENTANGLE-E0630"));
    }

    #[test]
    fn peer_descriptor_round_trips_equality() {
        let a = IrohPeer {
            peer_id: PeerId::from_public_key_bytes(&[1; 32]),
            addr: "127.0.0.1:1000".parse().unwrap(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}
