//! Transport-selection errors (`ENTANGLE-E0430`–`E0449`).
//!
//! These say *which* transports were considered for a peer and why each one
//! did not carry the request. The dispatcher wraps them in
//! [`DispatchError::RemoteTransport`](crate::DispatchError::RemoteTransport)
//! (`E0402`), so a remote dispatch that fails for a routing reason carries
//! both codes; streams carry them inside `StreamError::Transport` (`E0363`).

use entangle_types::peer_id::PeerId;

use super::TransportKind;

/// Why no transport carried a request to a peer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RouteError {
    /// `ENTANGLE-E0430` — no enabled, usable transport knows an address for
    /// the peer. Nothing was dialled.
    #[error(
        "ENTANGLE-E0430: no known network address for peer {peer} on any usable transport \
         (not paired, or no address learned yet): {detail}"
    )]
    NoRoute {
        /// The peer.
        peer: PeerId,
        /// Per transport, why it had no route (`tailscale: tailnet stopped
        /// (NeedsLogin)`, `iroh: not in the address book`, ...).
        detail: String,
    },

    /// `ENTANGLE-E0431` — every candidate transport failed while
    /// connecting, so the request was never delivered anywhere.
    #[error("ENTANGLE-E0431: could not connect to peer {peer} on any transport: {attempts}")]
    Unreachable {
        /// The peer.
        peer: PeerId,
        /// Per attempted transport, in order, why connecting failed.
        attempts: String,
        /// The last transport tried.
        last: TransportKind,
    },

    /// `ENTANGLE-E0432` — the transport failed after the request may have
    /// reached the peer. Not retried on another transport: the peer may have
    /// acted on it.
    #[error(
        "ENTANGLE-E0432: mesh.{transport} failed after the request was sent to peer {peer} \
         (not retried on another transport): {reason}"
    )]
    Failed {
        /// The peer.
        peer: PeerId,
        /// The transport that carried the request.
        transport: TransportKind,
        /// The transport's error.
        reason: String,
    },

    /// `ENTANGLE-E0433` — a frame (ours, or the peer's answer) was over the
    /// transport's frame cap; refused from its header.
    #[error(
        "ENTANGLE-E0433: a frame to or from peer {peer} over mesh.{transport} declares \
         {declared} bytes, cap is {max} bytes"
    )]
    FrameTooLarge {
        /// The peer.
        peer: PeerId,
        /// The transport that refused the frame.
        transport: TransportKind,
        /// The declared length.
        declared: u64,
        /// The cap in force.
        max: usize,
    },

    /// `ENTANGLE-E0434` — a transport name that is not `local`,
    /// `tailscale` or `iroh` (in `[mesh] preferred` or an override).
    #[error(
        "ENTANGLE-E0434: unknown transport {0:?} (expected \"local\", \"tailscale\" or \"iroh\")"
    )]
    UnknownTransport(String),

    /// `ENTANGLE-E0435` — a per-peer transport override that cannot be
    /// used (bad peer id, empty or repeated transport list).
    #[error("ENTANGLE-E0435: invalid per-peer transport override for {key:?}: {reason}")]
    BadOverride {
        /// The override's key as written.
        key: String,
        /// What is wrong with it.
        reason: String,
    },
}

impl RouteError {
    /// The stable `ENTANGLE-E043x` code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NoRoute { .. } => "ENTANGLE-E0430",
            Self::Unreachable { .. } => "ENTANGLE-E0431",
            Self::Failed { .. } => "ENTANGLE-E0432",
            Self::FrameTooLarge { .. } => "ENTANGLE-E0433",
            Self::UnknownTransport(_) => "ENTANGLE-E0434",
            Self::BadOverride { .. } => "ENTANGLE-E0435",
        }
    }

    /// The transport the failure happened on, if one was tried.
    pub const fn transport(&self) -> Option<TransportKind> {
        match self {
            Self::Unreachable { last, .. } => Some(*last),
            Self::Failed { transport, .. } | Self::FrameTooLarge { transport, .. } => {
                Some(*transport)
            }
            Self::NoRoute { .. } | Self::UnknownTransport(_) | Self::BadOverride { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_prefix_their_messages_and_are_unique() {
        let peer = PeerId::from_public_key_bytes(&[1; 32]);
        let all = [
            RouteError::NoRoute {
                peer,
                detail: "x".into(),
            },
            RouteError::Unreachable {
                peer,
                attempts: "x".into(),
                last: TransportKind::Iroh,
            },
            RouteError::Failed {
                peer,
                transport: TransportKind::Tailscale,
                reason: "x".into(),
            },
            RouteError::FrameTooLarge {
                peer,
                transport: TransportKind::Iroh,
                declared: 2,
                max: 1,
            },
            RouteError::UnknownTransport("x".into()),
            RouteError::BadOverride {
                key: "k".into(),
                reason: "r".into(),
            },
        ];
        let mut codes: Vec<_> = all.iter().map(RouteError::code).collect();
        for e in &all {
            assert!(e.to_string().starts_with(e.code()), "{e}");
        }
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len());
        assert!(all[0].to_string().contains("address"));
    }
}
