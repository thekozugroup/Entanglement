//! Tailscale-tailnet mesh transport for Entanglement (spec §6.1.1).
//!
//! `mesh.tailscale` reuses the Tailscale daemon already on the host:
//!
//! * [`status`] shells out to `tailscale status --json` and classifies the
//!   tailnet as `active` / `stopped(reason)` / `uninstalled`;
//! * [`liveness`] polls that on a 5 s cadence with hysteresis, a 30 s grace
//!   period and a 5-minute slow mode, publishing state on a `watch` channel
//!   and logging one event per transition;
//! * [`MeshTailscale`] carries identity-bound request/response traffic over
//!   TCP between tailnet IPs. WireGuard authenticates the *host*; a mutual
//!   Ed25519-signed X25519 key exchange authenticates the *Entanglement
//!   `PeerId`* and agrees per-session keys, and every frame after it is a
//!   ChaCha20-Poly1305 record. Trust decisions never rest on tailnet
//!   membership alone, and a tailnet node that relays a connection can
//!   neither read nor inject;
//! * discovery enumerates online tailnet peers and probes them with the
//!   handshake (see `MeshTailscale::discover`).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use entangle_types::peer_id::PeerId;

mod error;
mod framing;
mod handshake;
pub mod liveness;
pub mod status;
mod transport;

#[cfg(test)]
mod transport_tests;

pub use error::MeshTailscaleError;
pub use liveness::{
    spawn_liveness, Clock, LivenessConfig, LivenessHandle, LivenessMachine, LivenessSnapshot,
    TokioClock, Transition,
};
pub use status::{
    CliStatusSource, Observation, StatusSource, TailnetNode, TailnetState, TailscaleStatus,
};
pub use transport::{
    MeshConn, MeshRequest, MeshTailscale, PeerAllowlist, RequestHandler, StaticAllowlist,
};

/// Default TCP port for Entanglement over the tailnet.
pub const DEFAULT_PORT: u16 = 41643;

/// Hard ceiling on the configurable frame cap (64 MiB).
pub const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

/// Operator policy for layering Entanglement's own ACLs on top of the tailnet.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum AclMode {
    /// Entanglement enforces its own peer allowlist on top of Tailscale ACLs:
    /// an authenticated peer that is not allowlisted is dropped after the
    /// handshake, before any request is read. With no allowlist configured,
    /// every peer is rejected (fail closed).
    #[default]
    EntangleOnTop,
    /// Trust the tailnet ACL for reachability (only safe when the operator
    /// controls the tailnet end-to-end). Identity is still authenticated.
    TrustTailnet,
}

impl AclMode {
    /// Canonical config spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EntangleOnTop => "entangle-on-top",
            Self::TrustTailnet => "trust-tailnet",
        }
    }
}

impl FromStr for AclMode {
    type Err = String;

    /// Accepts `entangle-on-top`, `trust-tailnet` and the spec's older
    /// spelling `tailscale-only`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "entangle-on-top" => Ok(Self::EntangleOnTop),
            "trust-tailnet" | "tailscale-only" => Ok(Self::TrustTailnet),
            other => Err(format!(
                "unknown acl-mode {other:?} (expected \"entangle-on-top\" or \"trust-tailnet\")"
            )),
        }
    }
}

/// Configuration for the `mesh.tailscale` transport.
#[derive(Clone, Debug)]
pub struct MeshTailscaleConfig {
    /// Path to the `tailscale` CLI. Empty = use `$PATH`.
    pub tailscale_cli: String,
    /// ACL layering policy.
    pub acl_mode: AclMode,
    /// Peer allowlist consulted in [`AclMode::EntangleOnTop`].
    pub allowlist: Option<Arc<dyn PeerAllowlist>>,
    /// TCP port to listen on (and to probe on peers). `0` = ephemeral.
    pub port: u16,
    /// Local address to bind. Defaults to all interfaces; the handshake and
    /// allowlist protect the port either way, but binding the node's tailnet
    /// IP narrows exposure.
    pub bind_ip: IpAddr,
    /// Largest frame accepted or sent (clamped to [`MAX_FRAME_BYTES`]).
    pub max_frame_bytes: usize,
    /// TCP connect timeout.
    pub connect_timeout: Duration,
    /// Whole-handshake timeout.
    pub handshake_timeout: Duration,
    /// Per-request round-trip timeout.
    pub request_timeout: Duration,
    /// Server-side idle limit between requests on one connection.
    pub idle_timeout: Duration,
    /// Liveness poll timing.
    pub liveness: LivenessConfig,
}

impl Default for MeshTailscaleConfig {
    fn default() -> Self {
        Self {
            tailscale_cli: String::new(),
            acl_mode: AclMode::default(),
            allowlist: None,
            port: DEFAULT_PORT,
            bind_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            max_frame_bytes: 16 * 1024 * 1024,
            connect_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
            liveness: LivenessConfig::default(),
        }
    }
}

impl MeshTailscaleConfig {
    /// Resolve the configured CLI path to a command name for
    /// `std::process::Command::new()`.
    ///
    /// If `tailscale_cli` is set, returns it verbatim. Otherwise returns
    /// `"tailscale"` so the OS's `$PATH` lookup is used.
    pub fn resolve_cli(&self) -> &str {
        if self.tailscale_cli.is_empty() {
            "tailscale"
        } else {
            self.tailscale_cli.as_str()
        }
    }

    /// A [`CliStatusSource`] for the configured CLI.
    pub fn status_source(&self) -> CliStatusSource {
        CliStatusSource::new(self.resolve_cli())
    }

    /// Start the liveness poller against the real CLI and clock.
    pub fn spawn_liveness(&self) -> LivenessHandle {
        spawn_liveness(
            Arc::new(self.status_source()),
            Arc::new(TokioClock::default()),
            self.liveness,
        )
    }

    pub(crate) fn normalized(mut self) -> Self {
        self.max_frame_bytes = self.max_frame_bytes.min(MAX_FRAME_BYTES);
        self
    }
}

/// A tailnet peer that speaks Entanglement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TailscalePeer {
    /// Entanglement peer id, derived from `public_key`.
    pub peer_id: PeerId,
    /// The peer's Ed25519 public key (pinned when dialling).
    pub public_key: [u8; 32],
    /// Where to dial: tailnet IP and port.
    pub addr: std::net::SocketAddr,
    /// MagicDNS hostname (e.g. `bob-desktop.tail-scale.ts.net`), if known.
    pub magic_dns: String,
}

impl TailscalePeer {
    /// Build a descriptor; `peer_id` is derived from the key.
    pub fn new(public_key: [u8; 32], addr: std::net::SocketAddr) -> Self {
        Self {
            peer_id: PeerId::from_public_key_bytes(&public_key),
            public_key,
            addr,
            magic_dns: String::new(),
        }
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

    #[test]
    fn acl_mode_parses_both_spellings() {
        assert_eq!("entangle-on-top".parse(), Ok(AclMode::EntangleOnTop));
        assert_eq!("trust-tailnet".parse(), Ok(AclMode::TrustTailnet));
        assert_eq!("tailscale-only".parse(), Ok(AclMode::TrustTailnet));
        assert!("open".parse::<AclMode>().is_err());
    }

    #[test]
    fn resolve_cli_falls_back_to_path_when_empty() {
        let c = MeshTailscaleConfig::default();
        assert_eq!(c.resolve_cli(), "tailscale");
    }

    #[test]
    fn resolve_cli_returns_configured_path_when_set() {
        let c = MeshTailscaleConfig {
            tailscale_cli: "/opt/tailscale/bin/tailscale".into(),
            ..MeshTailscaleConfig::default()
        };
        assert_eq!(c.resolve_cli(), "/opt/tailscale/bin/tailscale");
    }

    #[test]
    fn frame_cap_is_clamped() {
        let c = MeshTailscaleConfig {
            max_frame_bytes: usize::MAX,
            ..MeshTailscaleConfig::default()
        }
        .normalized();
        assert_eq!(c.max_frame_bytes, MAX_FRAME_BYTES);
    }
}
