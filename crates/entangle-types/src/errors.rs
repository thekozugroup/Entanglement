//! Structured error types for the Entanglement architecture.
//!
//! Each variant carries a unique error code in the format `ENTANGLE-Exxxx`.
//!
//! # Error code ranges
//! | Range       | Domain                         |
//! |-------------|--------------------------------|
//! | E0042–E0043 | Tier violations                |
//! | E0100–E0122 | Authentication / authorisation |
//! | E0200–E0201 | Manifest / plugin id           |
//! | E0300–E0301 | Task execution                 |
//! | E0500       | I/O                            |
//! | E9999       | Internal / unexpected          |

use crate::tier::Tier;

/// All structured errors produced by the Entanglement stack.
#[derive(Debug, thiserror::Error)]
pub enum EntangleError {
    /// `ENTANGLE-E0042` — plugin declared a tier that is below the minimum
    /// required by one of its requested capabilities.
    #[error(
        "ENTANGLE-E0042: declared tier {declared:?} below implied tier {implied:?} \
         (capability {capability})"
    )]
    TierBelowCapability {
        /// The tier declared in the plugin manifest.
        declared: Tier,
        /// The minimum tier implied by the capability.
        implied: Tier,
        /// Human-readable capability identifier.
        capability: String,
    },

    /// `ENTANGLE-E0043` — plugin's tier exceeds the daemon's configured ceiling.
    #[error("ENTANGLE-E0043: tier {0:?} exceeds daemon max_tier_allowed {1:?}")]
    TierAboveDaemonCeiling(Tier, Tier),

    /// `ENTANGLE-E0100` — cryptographic signature verification failed.
    #[error("ENTANGLE-E0100: signature verification failed: {0}")]
    SignatureInvalid(String),

    /// `ENTANGLE-E0101` — the plugin publisher key is not in the daemon's trust roots.
    #[error("ENTANGLE-E0101: publisher key not in trust roots")]
    UntrustedPublisher,

    /// `ENTANGLE-E0120` — the plugin requested a capability it was not granted.
    #[error("ENTANGLE-E0120: capability {capability} not granted to plugin {plugin}")]
    CapabilityDenied {
        /// The denied capability surface string.
        capability: String,
        /// The plugin that made the request.
        plugin: String,
    },

    /// `ENTANGLE-E0122` — a bridge biscuit is missing a required attenuation caveat.
    #[error("ENTANGLE-E0122: bridge biscuit missing required attenuation: {0}")]
    BridgeAttenuationMissing(String),

    /// `ENTANGLE-E0200` — the plugin manifest could not be parsed or validated.
    #[error("ENTANGLE-E0200: manifest invalid: {0}")]
    ManifestInvalid(String),

    /// `ENTANGLE-E0201` — a plugin id string is not well-formed.
    #[error("ENTANGLE-E0201: plugin id format invalid: {0}")]
    PluginIdInvalid(String),

    /// `ENTANGLE-E0300` — a peer returned an output that exceeds the declared
    /// `max_output_bytes` limit.
    #[error(
        "ENTANGLE-E0300: output exceeds max_output_bytes \
         (declared {declared}, actual {actual}) from peer {peer}"
    )]
    OutputSizeExceeded {
        /// The limit declared in the task.
        declared: u64,
        /// The actual output size received.
        actual: u64,
        /// The peer that sent the oversized output.
        peer: String,
    },

    /// `ENTANGLE-E0301` — a task exceeded its configured wall-clock timeout.
    #[error("ENTANGLE-E0301: task timeout after {0}ms")]
    TaskTimeout(u64),

    /// `ENTANGLE-E0500` — an I/O error propagated from the standard library.
    #[error("ENTANGLE-E0500: io error: {0}")]
    Io(#[from] std::io::Error),

    /// `ENTANGLE-E9999` — an unexpected internal error.
    #[error("ENTANGLE-E9999: internal: {0}")]
    Internal(String),
}

/// Convenience alias: `Result<T>` using [`EntangleError`].
pub type Result<T> = std::result::Result<T, EntangleError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_messages_contain_code() {
        let e = EntangleError::TaskTimeout(5000);
        assert!(e.to_string().contains("ENTANGLE-E0301"));

        let e = EntangleError::UntrustedPublisher;
        assert!(e.to_string().contains("ENTANGLE-E0101"));

        let e = EntangleError::Internal("oops".into());
        assert!(e.to_string().contains("ENTANGLE-E9999"));
    }

    #[test]
    fn tier_below_capability_message() {
        let e = EntangleError::TierBelowCapability {
            declared: Tier::Pure,
            implied: Tier::Networked,
            capability: "net.wan".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("ENTANGLE-E0042"));
        assert!(msg.contains("net.wan"));
    }
}
