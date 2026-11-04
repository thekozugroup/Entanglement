//! Error type for the `mesh.tailscale` transport.
//!
//! Every variant carries a stable `ENTANGLE-E064x` code from the
//! `E0640–E0649` block. `E0640` and `E0641` were minted by the Phase-1
//! scaffold and keep their meaning; `E0642`–`E0649` belong to the real
//! transport. That block is full, so the version floor
//! ([`MeshTailscaleError::UnsupportedVersion`]) takes `ENTANGLE-E0791` from
//! the operator-flows block (`E0780–E0799`), which `entangle init` shares.

use std::net::SocketAddr;
use std::time::Duration;

/// Errors emitted by the `mesh.tailscale` transport.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MeshTailscaleError {
    /// `ENTANGLE-E0640` — retained for error-code stability.
    ///
    /// The Phase-1 scaffold returned this from `start()`. The transport is
    /// now real and no code path returns it, but the variant stays so the
    /// code is never recycled onto a different meaning.
    #[error("ENTANGLE-E0640: mesh.tailscale transport not implemented yet (Phase 2)")]
    NotImplemented,

    /// `ENTANGLE-E0641` — the tailscale CLI was not found.
    #[error("ENTANGLE-E0641: tailscale CLI not found in PATH")]
    NotInstalled,

    /// `ENTANGLE-E0642` — the local TCP listener could not be bound.
    #[error("ENTANGLE-E0642: cannot bind mesh.tailscale listener on {bind}: {reason}")]
    Bind {
        /// The address the transport tried to bind.
        bind: SocketAddr,
        /// Underlying OS failure, rendered as text.
        reason: String,
    },

    /// `ENTANGLE-E0643` — dialling a peer failed or timed out.
    #[error("ENTANGLE-E0643: cannot connect to {addr}: {reason}")]
    Connect {
        /// The address that could not be reached.
        addr: SocketAddr,
        /// Why (refused, timed out, ...).
        reason: String,
    },

    /// `ENTANGLE-E0644` — the identity handshake failed.
    ///
    /// Covers bad magic/version, a signature that does not verify, a remote
    /// key that is not the key we dialled, an invalid key, and handshake
    /// timeouts. The connection is dropped without reading any request.
    #[error("ENTANGLE-E0644: mesh.tailscale handshake failed: {0}")]
    Handshake(String),

    /// `ENTANGLE-E0645` — a frame declared a length above the cap.
    ///
    /// Raised **before** the body is allocated or read.
    #[error("ENTANGLE-E0645: frame declares {declared} bytes, cap is {max} bytes")]
    FrameTooLarge {
        /// Length claimed by the frame header.
        declared: u64,
        /// The cap in force for this connection.
        max: usize,
    },

    /// `ENTANGLE-E0646` — the peer sent a malformed or truncated frame.
    #[error("ENTANGLE-E0646: mesh.tailscale protocol violation: {0}")]
    Protocol(String),

    /// `ENTANGLE-E0647` — an I/O error, or a request exceeded its deadline.
    #[error("ENTANGLE-E0647: mesh.tailscale stream error: {0}")]
    Stream(String),

    /// `ENTANGLE-E0648` — the authenticated peer is not on the allowlist
    /// (`acl-mode = "entangle-on-top"`).
    #[error("ENTANGLE-E0648: peer {0} is authenticated but not in the peer allowlist")]
    PeerNotAllowed(entangle_types::peer_id::PeerId),

    /// `ENTANGLE-E0649` — `tailscale status --json` failed or was unparsable.
    #[error("ENTANGLE-E0649: tailscale status unavailable: {0}")]
    Status(String),

    /// `ENTANGLE-E0791` — the host's `tailscale` is older than
    /// [`crate::MIN_SUPPORTED_VERSION`] (spec §11 #17). The transport is not
    /// enabled on it, by `entangle init` or by the daemon at boot.
    #[error(
        "ENTANGLE-E0791: tailscale {found} is older than the supported minimum {minimum}; \
         upgrade Tailscale (https://tailscale.com/download), or drop the transport with \
         `entangle config set mesh.tailscale.enabled false`"
    )]
    UnsupportedVersion {
        /// The version `tailscale version` reported.
        found: crate::TailscaleVersion,
        /// The minimum this build supports.
        minimum: crate::TailscaleVersion,
    },
}

impl MeshTailscaleError {
    /// The stable `ENTANGLE-Exxxx` code for this error.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NotImplemented => "ENTANGLE-E0640",
            Self::NotInstalled => "ENTANGLE-E0641",
            Self::Bind { .. } => "ENTANGLE-E0642",
            Self::Connect { .. } => "ENTANGLE-E0643",
            Self::Handshake(_) => "ENTANGLE-E0644",
            Self::FrameTooLarge { .. } => "ENTANGLE-E0645",
            Self::Protocol(_) => "ENTANGLE-E0646",
            Self::Stream(_) => "ENTANGLE-E0647",
            Self::PeerNotAllowed(_) => "ENTANGLE-E0648",
            Self::Status(_) => "ENTANGLE-E0649",
            Self::UnsupportedVersion { .. } => "ENTANGLE-E0791",
        }
    }

    pub(crate) fn request_timeout(after: Duration) -> Self {
        Self::Stream(format!("request timed out after {}ms", after.as_millis()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use entangle_types::peer_id::PeerId;

    fn all() -> Vec<MeshTailscaleError> {
        vec![
            MeshTailscaleError::NotImplemented,
            MeshTailscaleError::NotInstalled,
            MeshTailscaleError::Bind {
                bind: "127.0.0.1:1".parse().unwrap(),
                reason: "x".into(),
            },
            MeshTailscaleError::Connect {
                addr: "127.0.0.1:1".parse().unwrap(),
                reason: "x".into(),
            },
            MeshTailscaleError::Handshake("x".into()),
            MeshTailscaleError::FrameTooLarge {
                declared: 1,
                max: 0,
            },
            MeshTailscaleError::Protocol("x".into()),
            MeshTailscaleError::Stream("x".into()),
            MeshTailscaleError::PeerNotAllowed(PeerId::from_public_key_bytes(&[1; 32])),
            MeshTailscaleError::Status("x".into()),
            MeshTailscaleError::UnsupportedVersion {
                found: crate::TailscaleVersion::new(1, 50, 0),
                minimum: crate::MIN_SUPPORTED_VERSION,
            },
        ]
    }

    #[test]
    fn code_matches_display_prefix_and_is_unique() {
        let errs = all();
        let mut codes = Vec::new();
        for e in &errs {
            assert!(e.to_string().starts_with(e.code()), "{e}");
            codes.push(e.code());
        }
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), errs.len());
    }
}
