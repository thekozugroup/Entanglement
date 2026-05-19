//! Tailscale-tailnet mesh transport for Entanglement (scaffold).
//!
//! Spec §6.1.1 names `mesh.tailscale` as the WAN-capable transport that
//! piggybacks on the operator's existing Tailscale tailnet. This crate is
//! the scaffold: it pins the public surface and returns
//! [`MeshTailscaleError::NotImplemented`] until Phase 2 wires
//! `tailscale status --json` plus MagicDNS SRV/TXT discovery.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use entangle_types::peer_id::PeerId;

/// Operator policy for layering Entanglement's own ACLs on top of the tailnet.
///
/// `entangle-on-top` (the recommended default) re-checks every peer against
/// the local allowlist + biscuits regardless of what the tailnet ACL allows.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum AclMode {
    /// Entanglement enforces its own peer allowlist on top of Tailscale ACLs.
    #[default]
    EntangleOnTop,
    /// Trust the tailnet ACL entirely (only safe when the operator controls
    /// the tailnet end-to-end).
    TrustTailnet,
}

/// Configuration for the `mesh.tailscale` transport.
#[derive(Clone, Debug, Default)]
pub struct MeshTailscaleConfig {
    /// Path to the `tailscale` CLI. Empty = use `$PATH`.
    pub tailscale_cli: String,
    /// ACL layering policy.
    pub acl_mode: AclMode,
}

/// Errors emitted by the scaffold.
#[derive(Debug, thiserror::Error)]
pub enum MeshTailscaleError {
    /// The transport is not yet implemented (Phase 2).
    #[error("ENTANGLE-E0640: mesh.tailscale transport not implemented yet (Phase 2)")]
    NotImplemented,
    /// `tailscaled` was not detected on this host.
    #[error("ENTANGLE-E0641: tailscale CLI not found in PATH")]
    NotInstalled,
}

/// Lightweight tailnet peer descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TailscalePeer {
    /// Entanglement peer id (Ed25519 public-key bytes).
    pub peer_id: PeerId,
    /// MagicDNS hostname (e.g. `bob-desktop.tail-scale.ts.net`).
    pub magic_dns: String,
}

/// Scaffolded transport handle.
#[derive(Debug, Default)]
pub struct MeshTailscale {
    config: MeshTailscaleConfig,
}

impl MeshTailscale {
    /// Construct a new transport with the given config.
    pub const fn new(config: MeshTailscaleConfig) -> Self {
        Self { config }
    }

    /// Borrow the active config.
    pub const fn config(&self) -> &MeshTailscaleConfig {
        &self.config
    }

    /// Start the transport.
    ///
    /// Phase 1: returns [`MeshTailscaleError::NotImplemented`].
    pub async fn start(&self) -> Result<(), MeshTailscaleError> {
        let _ = &self.config;
        Err(MeshTailscaleError::NotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_acl_mode_is_entangle_on_top() {
        let c = MeshTailscaleConfig::default();
        assert_eq!(c.acl_mode, AclMode::EntangleOnTop);
    }

    #[tokio::test]
    async fn start_returns_not_implemented_in_phase_1() {
        let t = MeshTailscale::new(MeshTailscaleConfig::default());
        let err = t.start().await.expect_err("Phase 1 must reject start");
        assert!(matches!(err, MeshTailscaleError::NotImplemented));
        assert!(err.to_string().contains("ENTANGLE-E0640"));
    }
}
