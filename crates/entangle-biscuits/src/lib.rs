//! Capability tokens (biscuits) for cross-node authorization.
//!
//! See `docs/architecture.md` §6.4 (bridge attenuation) and §6.5 (revocation).
//!
//! Implements spec §6 (capability delegation) and §6.4 (bridge cap attenuation rules).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bridge;
pub mod claims;
/// Error types for the `entangle-biscuits` crate.
pub mod errors;
pub mod mint;
pub mod verifier;

pub use bridge::{
    make_bridge_attenuation, verify_bridge_cap, BridgeError, BridgeFacts, BridgeVerifyContext,
    BRIDGE_RATE_LIMIT_MAX_BPS, BRIDGE_TOTAL_BYTES_MAX, BRIDGE_TTL_MAX_SECS,
};
pub use claims::{Claim, ClaimSet};
pub use errors::BiscuitError;
pub use mint::{attenuate_biscuit, mint};
pub use verifier::{parse, verify, ExtractedFacts, VerifyContext};

/// Re-export the biscuit-auth public key type for use by callers (e.g. entangle-broker).
pub use biscuit_auth::PublicKey;
