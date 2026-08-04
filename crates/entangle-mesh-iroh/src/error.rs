//! Error type for the `mesh.iroh` transport.
//!
//! Every variant carries a stable `ENTANGLE-E06xx` code. `E0630`/`E0631` were
//! minted by the Phase-1 scaffold and keep their meaning; `E0632`–`E0639` are
//! the transport's own, taken from the free part of the `E0600–E0699` block
//! documented in `entangle_types::errors` (`E0600–E0602`, `E0610`, `E0620–E0622`,
//! `E0640–E0641` and `E0650–E0652` are claimed elsewhere in the workspace).

use std::time::Duration;

/// Errors emitted by the `mesh.iroh` transport.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MeshIrohError {
    /// `ENTANGLE-E0630` — retained for error-code stability.
    ///
    /// The Phase-1 scaffold returned this from `MeshIroh::start()`. The
    /// transport is now real and no code path in this crate returns it any
    /// more, but the variant stays so that `ENTANGLE-E0630` continues to
    /// identify exactly one variant rather than being recycled onto a
    /// different meaning (see the stability rules in `entangle_types::errors`).
    #[error("ENTANGLE-E0630: mesh.iroh transport not implemented yet (Phase 2)")]
    NotImplemented,

    /// `ENTANGLE-E0631` — a node-addr string failed to parse.
    #[error("ENTANGLE-E0631: bad node-addr: {0}")]
    BadNodeAddr(&'static str),

    /// `ENTANGLE-E0632` — the local QUIC endpoint could not be bound.
    #[error("ENTANGLE-E0632: cannot bind mesh.iroh endpoint on {bind}: {reason}")]
    Bind {
        /// The socket address the transport tried to bind.
        bind: std::net::SocketAddr,
        /// Underlying iroh bind failure, rendered as text.
        ///
        /// Kept as text rather than a typed source so that iroh's error types
        /// stay out of this crate's public API.
        reason: String,
    },

    /// `ENTANGLE-E0633` — dialling a peer failed.
    #[error("ENTANGLE-E0633: cannot connect to peer {peer}: {reason}")]
    Connect {
        /// The peer that could not be reached.
        peer: entangle_types::peer_id::PeerId,
        /// Underlying iroh connect failure, rendered as text.
        reason: String,
    },

    /// `ENTANGLE-E0634` — dialling a peer exceeded the configured deadline.
    ///
    /// Distinct from [`MeshIrohError::Connect`] on purpose: a timeout means
    /// "no answer", which for the pairing UX is a different remediation
    /// (check the address / NAT) than an outright refusal.
    #[error("ENTANGLE-E0634: connect to peer {peer} timed out after {}ms", .after.as_millis())]
    ConnectTimeout {
        /// The peer that did not answer.
        peer: entangle_types::peer_id::PeerId,
        /// How long the transport waited.
        after: Duration,
    },

    /// `ENTANGLE-E0635` — a QUIC stream could not be opened, written or read.
    #[error("ENTANGLE-E0635: mesh.iroh stream error: {0}")]
    Stream(String),

    /// `ENTANGLE-E0636` — a frame declared a length above the negotiated cap.
    ///
    /// Raised **before** the body is allocated or read: the length prefix is
    /// untrusted input from a remote peer and is therefore validated first.
    #[error("ENTANGLE-E0636: frame declares {declared} bytes, cap is {max} bytes")]
    FrameTooLarge {
        /// Length claimed by the frame header.
        declared: u64,
        /// The cap in force for this connection.
        max: usize,
    },

    /// `ENTANGLE-E0637` — the peer sent a malformed or truncated frame.
    #[error("ENTANGLE-E0637: mesh.iroh protocol violation: {0}")]
    Protocol(String),

    /// `ENTANGLE-E0638` — the operation timed out after the connection was up.
    #[error("ENTANGLE-E0638: mesh.iroh request timed out after {}ms", .0.as_millis())]
    RequestTimeout(Duration),

    /// `ENTANGLE-E0639` — an identity key could not be converted into a QUIC
    /// node identity, or a peer presented an identity we cannot represent.
    #[error("ENTANGLE-E0639: mesh.iroh identity error: {0}")]
    Identity(String),
}

impl MeshIrohError {
    /// The stable `ENTANGLE-E06xx` code for this error.
    ///
    /// Provided so callers (CLI, observability) can branch or aggregate on the
    /// code without string-matching the `Display` output.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NotImplemented => "ENTANGLE-E0630",
            Self::BadNodeAddr(_) => "ENTANGLE-E0631",
            Self::Bind { .. } => "ENTANGLE-E0632",
            Self::Connect { .. } => "ENTANGLE-E0633",
            Self::ConnectTimeout { .. } => "ENTANGLE-E0634",
            Self::Stream(_) => "ENTANGLE-E0635",
            Self::FrameTooLarge { .. } => "ENTANGLE-E0636",
            Self::Protocol(_) => "ENTANGLE-E0637",
            Self::RequestTimeout(_) => "ENTANGLE-E0638",
            Self::Identity(_) => "ENTANGLE-E0639",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use entangle_types::peer_id::PeerId;

    /// Every variant's `code()` must be the prefix of its rendered message.
    /// This is what makes log-grepping by code trustworthy.
    #[test]
    fn code_matches_display_prefix() {
        let peer = PeerId::from_public_key_bytes(&[7; 32]);
        let all = [
            MeshIrohError::NotImplemented,
            MeshIrohError::BadNodeAddr("x"),
            MeshIrohError::Bind {
                bind: "127.0.0.1:0".parse().unwrap(),
                reason: "boom".into(),
            },
            MeshIrohError::Connect {
                peer,
                reason: "boom".into(),
            },
            MeshIrohError::ConnectTimeout {
                peer,
                after: Duration::from_millis(5),
            },
            MeshIrohError::Stream("boom".into()),
            MeshIrohError::FrameTooLarge {
                declared: 1,
                max: 0,
            },
            MeshIrohError::Protocol("boom".into()),
            MeshIrohError::RequestTimeout(Duration::from_millis(5)),
            MeshIrohError::Identity("boom".into()),
        ];
        for err in &all {
            let rendered = err.to_string();
            assert!(
                rendered.starts_with(err.code()),
                "{rendered} must start with {}",
                err.code()
            );
        }
    }

    /// Codes must be unique within the enum — a duplicate would make the
    /// code useless as an identifier.
    #[test]
    fn codes_are_unique() {
        let peer = PeerId::from_public_key_bytes(&[7; 32]);
        let codes = [
            MeshIrohError::NotImplemented.code(),
            MeshIrohError::BadNodeAddr("x").code(),
            MeshIrohError::Bind {
                bind: "127.0.0.1:0".parse().unwrap(),
                reason: String::new(),
            }
            .code(),
            MeshIrohError::Connect {
                peer,
                reason: String::new(),
            }
            .code(),
            MeshIrohError::ConnectTimeout {
                peer,
                after: Duration::ZERO,
            }
            .code(),
            MeshIrohError::Stream(String::new()).code(),
            MeshIrohError::FrameTooLarge {
                declared: 0,
                max: 0,
            }
            .code(),
            MeshIrohError::Protocol(String::new()).code(),
            MeshIrohError::RequestTimeout(Duration::ZERO).code(),
            MeshIrohError::Identity(String::new()).code(),
        ];
        let mut sorted = codes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len(), "duplicate ENTANGLE-E06xx code");
    }
}
