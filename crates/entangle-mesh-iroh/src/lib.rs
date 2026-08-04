//! WAN Iroh-QUIC mesh transport for Entanglement.
//!
//! Spec §6.1 names `mesh.iroh` as the WAN-capable transport: QUIC over direct
//! UDP, hole-punched UDP, and relayed TCP. This crate is that transport, built
//! on [`iroh`] 1.0.
//!
//! # What it gives the rest of the workspace
//!
//! * [`MeshTransport`] — a transport-shaped trait in terms of [`PeerId`] and
//!   byte payloads. No iroh type appears in its signatures, so the dispatcher
//!   and the pairing flow depend on the *concept* of a peer transport, not on
//!   iroh. [`DynMeshTransport`] is the boxed alias for storing one.
//! * [`MeshIroh`] — the iroh implementation.
//! * [`MeshConn`] / [`MeshRequest`] — one connection and one inbound request.
//! * [`serve`] — the server-side accept loop, for callers that just want a
//!   handler.
//!
//! # Identity binding
//!
//! iroh derives its node identity (`EndpointId`) from an Ed25519 secret key.
//! [`MeshIroh::start`] hands it the daemon's own [`IdentityKeyPair`], so:
//!
//! ```text
//! iroh EndpointId bytes == IdentityPublicKey bytes
//! PeerId::from_public_key_bytes(EndpointId) == the daemon's PeerId
//! ```
//!
//! That equality is what lets a peer's QUIC-authenticated identity be fed
//! straight into the existing trust model — there is no second namespace of
//! network identifiers to reconcile. It is asserted mechanically in
//! `tests/loopback.rs::observed_peer_id_matches_ed25519_identity`.
//!
//! # Wire protocol
//!
//! ALPN selects the sub-protocol (spec §6.7): [`ALPN_CONTROL`],
//! [`ALPN_SCHEDULER`], [`ALPN_AGENT`], [`ALPN_BLOBS`], [`ALPN_DOCS`]. One
//! transport instance serves one ALPN; run several for several protocols.
//!
//! On a stream, messages are length-prefixed — `u32` big-endian length then
//! payload — capped at [`MAX_FRAME_BYTES`]. The cap is enforced against the
//! header before any allocation; see the threat-model note on the framing
//! module.
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use entangle_mesh_iroh::{MeshIroh, MeshIrohConfig, MeshTransport, parse_node_addr};
//! use entangle_signing::IdentityKeyPair;
//!
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let identity = IdentityKeyPair::generate();
//! let transport = Arc::new(MeshIroh::start(MeshIrohConfig::default(), &identity).await?);
//!
//! // Server half: echo every request.
//! let server = Arc::clone(&transport);
//! tokio::spawn(entangle_mesh_iroh::serve(server, |_peer, bytes| async move { bytes }));
//!
//! // Client half.
//! let peer = parse_node_addr("00ff…@192.0.2.7:41641")?;
//! let reply = transport.request(&peer, b"ping").await?;
//! assert_eq!(reply, b"ping");
//! # Ok(())
//! # }
//! ```
//!
//! [`IdentityKeyPair`]: entangle_signing::IdentityKeyPair

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod framing;
mod peer;
mod transport;

use std::net::SocketAddr;
use std::time::Duration;

use entangle_types::peer_id::PeerId;
use entangle_types::task::OneShotTask;

pub use crate::error::MeshIrohError;
pub use crate::peer::{format_node_addr, parse_node_addr, IrohPeer};
pub use crate::transport::{serve, MeshConn, MeshIroh, MeshRequest};

/// ALPN for mesh membership / control traffic (spec §6.7). The default.
pub const ALPN_CONTROL: &[u8] = b"entangle/control/1";
/// ALPN for scheduler work dispatch (spec §6.7).
pub const ALPN_SCHEDULER: &[u8] = b"entangle/scheduler/1";
/// ALPN for agent-to-agent traffic (spec §6.7).
pub const ALPN_AGENT: &[u8] = b"entangle/agent/1";
/// ALPN for blob transfer (spec §6.7).
pub const ALPN_BLOBS: &[u8] = b"entangle/blobs/1";
/// ALPN for shared-storage / docs traffic (spec §6.7).
pub const ALPN_DOCS: &[u8] = b"entangle/docs/1";

/// Hard ceiling on a single frame's payload, in bytes: 16 MiB + 64 KiB.
///
/// Derived from the same reasoning as `entangle_bin::server::MAX_REQUEST_BYTES`
/// but *without* its 4x factor. That constant sizes a JSON-encoded request
/// line, where a byte array inflates to `[255,255,…]`; mesh frames carry the
/// bytes raw. So the ceiling is one maximum task input
/// ([`OneShotTask::DEFAULT_MAX_INPUT_BYTES`], 16 MiB) plus 64 KiB of envelope
/// headroom — the largest legal payload, and nothing more.
///
/// This is a remote attack surface: the length prefix is attacker-controlled,
/// so it is checked before allocation and a frame over the cap is rejected
/// rather than truncated.
pub const MAX_FRAME_BYTES: usize = OneShotTask::DEFAULT_MAX_INPUT_BYTES as usize + 64 * 1024;

/// Default deadline for establishing a connection.
///
/// iroh gives up on an unreachable direct address after roughly 10s; this sits
/// just outside that so a genuinely unreachable peer surfaces as
/// [`MeshIrohError::Connect`] where possible and
/// [`MeshIrohError::ConnectTimeout`] as the backstop. Either way the caller
/// gets a typed error instead of a hang.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Default deadline for one request/response round-trip on a live connection.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration for the `mesh.iroh` transport.
#[derive(Clone, Debug)]
pub struct MeshIrohConfig {
    /// Local endpoint to bind. `0` selects an ephemeral port.
    pub bind: SocketAddr,
    /// Whether to enable relay fallback (slower path; used when hole-punching
    /// fails). Maps to iroh's `RelayMode::Default` vs `RelayMode::Disabled`.
    ///
    /// Named for DERP, iroh's original relay protocol, because that is the
    /// name §6.1 uses.
    pub allow_derp_relay: bool,
    /// ALPN this transport speaks. One of the `ALPN_*` constants.
    pub alpn: Vec<u8>,
    /// Deadline for [`MeshTransport::connect`].
    pub connect_timeout: Duration,
    /// Deadline for one [`MeshConn::request`] round-trip.
    pub request_timeout: Duration,
    /// Per-frame payload cap. Clamped to [`MAX_FRAME_BYTES`]; a smaller value
    /// is honoured, a larger one is not.
    pub max_frame_bytes: usize,
}

impl Default for MeshIrohConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:0".parse().expect("default bind parses"),
            allow_derp_relay: true,
            alpn: ALPN_CONTROL.to_vec(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_frame_bytes: MAX_FRAME_BYTES,
        }
    }
}

impl MeshIrohConfig {
    /// A config for loopback-only use: no relay, no discovery, bound to
    /// `127.0.0.1:0`.
    ///
    /// This is what the in-process tests use, and what a single-machine
    /// integration harness wants: it never touches the public internet.
    pub fn loopback() -> Self {
        Self {
            bind: "127.0.0.1:0".parse().expect("loopback bind parses"),
            allow_derp_relay: false,
            ..Self::default()
        }
    }

    /// Return a copy with out-of-range values clamped into range.
    ///
    /// Applied by [`MeshIroh::start`], so a config that asks for a 1 GiB frame
    /// cap silently gets [`MAX_FRAME_BYTES`] instead of a remote-triggerable
    /// allocation.
    #[must_use]
    pub fn normalized(mut self) -> Self {
        self.max_frame_bytes = self.max_frame_bytes.clamp(1, MAX_FRAME_BYTES);
        self
    }
}

/// A peer-to-peer transport, in terms the rest of the workspace can use.
///
/// Object-safe (via `async_trait`), so it can be stored as
/// [`DynMeshTransport`]. Implemented here by [`MeshIroh`]; a Tailscale or
/// in-memory-test transport can implement the same surface.
#[async_trait::async_trait]
pub trait MeshTransport: std::fmt::Debug + Send + Sync {
    /// This node's [`PeerId`].
    fn local_peer_id(&self) -> PeerId;

    /// This node's raw Ed25519 public key (equal to its iroh `EndpointId`).
    fn local_public_key(&self) -> [u8; 32];

    /// The socket addresses this node is actually bound to.
    fn local_addrs(&self) -> Vec<SocketAddr>;

    /// Dial `peer` and complete the handshake.
    async fn connect(&self, peer: &IrohPeer) -> Result<MeshConn, MeshIrohError>;

    /// Dial `peer`, send one framed request, return the framed response, and
    /// close the connection.
    ///
    /// The convenience path for one-shot cross-node dispatch. For repeated
    /// traffic to the same peer, hold a [`MeshConn`] from
    /// [`MeshTransport::connect`] instead.
    async fn request(&self, peer: &IrohPeer, payload: &[u8]) -> Result<Vec<u8>, MeshIrohError>;

    /// Wait for the next inbound connection.
    ///
    /// Returns `Ok(None)` once the transport has been shut down, which is the
    /// signal for an accept loop to exit.
    async fn accept(&self) -> Result<Option<MeshConn>, MeshIrohError>;

    /// Close the endpoint, flushing connection-close frames to peers.
    async fn shutdown(&self);
}

/// Boxed [`MeshTransport`], for callers that store one without naming the
/// implementation.
pub type DynMeshTransport = std::sync::Arc<dyn MeshTransport>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_binds_wildcard_ephemeral() {
        let c = MeshIrohConfig::default();
        assert_eq!(c.bind.port(), 0);
        assert!(c.allow_derp_relay);
        assert_eq!(c.alpn, ALPN_CONTROL);
    }

    #[test]
    fn loopback_config_is_offline() {
        let c = MeshIrohConfig::loopback();
        assert!(c.bind.ip().is_loopback());
        assert!(!c.allow_derp_relay, "loopback must not dial relays");
    }

    #[test]
    fn normalized_clamps_frame_cap() {
        let c = MeshIrohConfig {
            max_frame_bytes: usize::MAX,
            ..MeshIrohConfig::default()
        }
        .normalized();
        assert_eq!(c.max_frame_bytes, MAX_FRAME_BYTES);

        let small = MeshIrohConfig {
            max_frame_bytes: 128,
            ..MeshIrohConfig::default()
        }
        .normalized();
        assert_eq!(small.max_frame_bytes, 128, "smaller caps are honoured");

        let zero = MeshIrohConfig {
            max_frame_bytes: 0,
            ..MeshIrohConfig::default()
        }
        .normalized();
        assert_eq!(zero.max_frame_bytes, 1);
    }

    #[test]
    fn frame_cap_matches_documented_derivation() {
        assert_eq!(MAX_FRAME_BYTES, 16 * 1024 * 1024 + 64 * 1024);
    }

    /// The ALPN strings are wire-visible and must match spec §6.7 exactly;
    /// changing one silently partitions a mesh.
    #[test]
    fn alpn_strings_match_spec() {
        assert_eq!(ALPN_CONTROL, b"entangle/control/1");
        assert_eq!(ALPN_SCHEDULER, b"entangle/scheduler/1");
        assert_eq!(ALPN_AGENT, b"entangle/agent/1");
        assert_eq!(ALPN_BLOBS, b"entangle/blobs/1");
        assert_eq!(ALPN_DOCS, b"entangle/docs/1");
    }

    /// `MeshTransport` must stay object-safe: the dispatcher stores one.
    #[test]
    fn transport_trait_is_object_safe() {
        fn assert_boxable(_: Option<DynMeshTransport>) {}
        assert_boxable(None);
    }
}
