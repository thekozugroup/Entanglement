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
    /// A node-addr string failed to parse.
    #[error("ENTANGLE-E0631: bad node-addr: {0}")]
    BadNodeAddr(&'static str),
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

/// Parse a `<peer_id_hex>@<host>:<port>` reference into an [`IrohPeer`].
///
/// This is the operator-facing form printed by `entangle mesh peers` and
/// accepted by `entangle mesh trust <node-addr>`. Spec §6.1 calls it
/// the "long address" — it bundles the cryptographic identity and a
/// reachability hint.
pub fn parse_node_addr(s: &str) -> Result<IrohPeer, MeshIrohError> {
    let (id_hex, addr_str) = s
        .split_once('@')
        .ok_or(MeshIrohError::BadNodeAddr("missing '@' separator"))?;
    if id_hex.len() != 64 {
        return Err(MeshIrohError::BadNodeAddr(
            "peer id hex must be 64 chars (32 bytes)",
        ));
    }
    let mut bytes = [0u8; 32];
    for (i, chunk) in id_hex.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk)
            .map_err(|_| MeshIrohError::BadNodeAddr("non-ASCII in peer id"))?;
        bytes[i] = u8::from_str_radix(pair, 16)
            .map_err(|_| MeshIrohError::BadNodeAddr("invalid hex digit in peer id"))?;
    }
    let addr: SocketAddr = addr_str
        .parse()
        .map_err(|_| MeshIrohError::BadNodeAddr("addr must be host:port"))?;
    Ok(IrohPeer {
        peer_id: PeerId::from_public_key_bytes(&bytes),
        addr,
    })
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

    #[test]
    fn parse_node_addr_round_trips_well_formed() {
        let hex = "a".repeat(64);
        let s = format!("{hex}@10.0.0.1:7777");
        let peer = parse_node_addr(&s).expect("parse must succeed");
        assert_eq!(peer.addr.port(), 7777);
        assert_eq!(
            peer.peer_id,
            PeerId::from_public_key_bytes(&[0xaa; 32]),
            "every nibble 'a' = byte 0xaa"
        );
    }

    #[test]
    fn parse_node_addr_rejects_missing_at() {
        let err = parse_node_addr("abcdef").expect_err("must error");
        assert!(matches!(err, MeshIrohError::BadNodeAddr(_)));
        assert!(err.to_string().contains("ENTANGLE-E0631"));
    }

    #[test]
    fn parse_node_addr_rejects_short_hex() {
        let err = parse_node_addr("abcd@127.0.0.1:1").expect_err("must error");
        assert!(matches!(err, MeshIrohError::BadNodeAddr(_)));
    }

    #[test]
    fn parse_node_addr_rejects_bad_addr() {
        let hex = "0".repeat(64);
        let err = parse_node_addr(&format!("{hex}@not-an-addr")).expect_err("must error");
        assert!(matches!(err, MeshIrohError::BadNodeAddr(_)));
    }
}
