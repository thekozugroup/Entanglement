//! Bridge cap attenuation rules (spec §6.4).
//!
//! When a node delegates a capability across a transport boundary (e.g.
//! relaying a tier-3 GPU compute cap from a tailscale peer to a LAN peer), the
//! bridge MUST attenuate the original biscuit with five mandatory facts:
//!
//! 1. `dest_pin("<peer-id-hex>")` — the relay only carries traffic for one
//!    specific destination peer.
//! 2. `rate_limit_bps(N)` — max bytes/sec, N <= 1_073_741_824 (1 GiB/s).
//! 3. `total_bytes_cap(N)` — lifetime byte cap, N <= 1_099_511_627_776 (1 TiB).
//! 4. `expires(T)` — T - now <= 3600 (1 hour).
//! 5. `bridge(true)` — explicit marker.
//!
//! [`verify_bridge_cap`] enforces all five before returning ok. A cap missing
//! ANY of them, or with values outside the bounds, is rejected with a precise
//! [`BridgeError`] variant.

use biscuit_auth::PublicKey;
use entangle_types::peer_id::PeerId;

use crate::{
    claims::ClaimSet,
    errors::BiscuitError,
    verifier::{parse, verify, VerifyContext},
};

// ─── Constants ──────────────────────────────────────────────────────────────

/// Maximum TTL for a bridge cap: 1 hour (spec §6.4).
pub const BRIDGE_TTL_MAX_SECS: i64 = 3_600;

/// Maximum rate limit for a bridge cap: 1 GiB/s.
pub const BRIDGE_RATE_LIMIT_MAX_BPS: u64 = 1_073_741_824;

/// Maximum lifetime byte cap for a bridge cap: 1 TiB.
pub const BRIDGE_TOTAL_BYTES_MAX: u64 = 1_099_511_627_776;

// ─── Error type ─────────────────────────────────────────────────────────────

/// Errors specific to bridge cap verification.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    /// ENTANGLE-E0420: a required bridge attenuation fact is missing.
    #[error("ENTANGLE-E0420: bridge cap missing required fact: {0}")]
    AttenuationMissing(&'static str),
    /// ENTANGLE-E0421: the bridge TTL exceeds the 1-hour ceiling.
    #[error("ENTANGLE-E0421: bridge TTL {ttl}s exceeds maximum {max}s")]
    TtlTooLong {
        /// Actual TTL in seconds.
        ttl: i64,
        /// Maximum allowed TTL in seconds.
        max: i64,
    },
    /// ENTANGLE-E0422: rate_limit_bps exceeds the 1 GiB/s ceiling.
    #[error("ENTANGLE-E0422: bridge rate_limit_bps {actual} exceeds maximum {max}")]
    RateLimitTooHigh {
        /// Actual rate limit in bytes per second.
        actual: u64,
        /// Maximum allowed rate limit in bytes per second.
        max: u64,
    },
    /// ENTANGLE-E0423: total_bytes_cap exceeds the 1 TiB ceiling.
    #[error("ENTANGLE-E0423: bridge total_bytes_cap {actual} exceeds maximum {max}")]
    TotalBytesTooLarge {
        /// Actual total bytes cap.
        actual: u64,
        /// Maximum allowed total bytes cap.
        max: u64,
    },
    /// ENTANGLE-E0424: dest_pin peer does not match the expected destination.
    #[error("ENTANGLE-E0424: dest_pin '{got}' != expected destination '{expected}'")]
    DestPinMismatch {
        /// The dest_pin value found in the token.
        got: String,
        /// The expected destination peer hex.
        expected: String,
    },
    /// Wraps a lower-level biscuit error.
    #[error("biscuit: {0}")]
    Biscuit(#[from] BiscuitError),
}

// ─── Context / result types ─────────────────────────────────────────────────

/// Context required to verify a bridge cap.
#[derive(Clone, Debug)]
pub struct BridgeVerifyContext {
    /// Unix timestamp (seconds) representing "now".
    pub now_unix_secs: i64,
    /// Identity of the local bridge node.
    pub local_peer_id: PeerId,
    /// The destination peer the bridge claims to relay for.
    pub expected_destination: PeerId,
    /// The capability surface name that must be present.
    pub require_capability: String,
}

/// Typed facts extracted from a verified bridge cap.
#[derive(Clone, Debug)]
pub struct BridgeFacts {
    /// All capability surface names present in the token.
    pub capabilities: Vec<String>,
    /// The pinned destination peer.
    pub dest_pin: PeerId,
    /// Max bytes/sec granted.
    pub rate_limit_bps: u64,
    /// Lifetime byte cap.
    pub total_bytes_cap: u64,
    /// Absolute expiry as a Unix timestamp.
    pub expires: i64,
}

// ─── Public API ─────────────────────────────────────────────────────────────

/// Verify a bridge cap. Enforces all 5 mandatory attenuations and bounded values.
///
/// Returns [`BridgeFacts`] on success, or a [`BridgeError`] describing the
/// first violated constraint.
pub fn verify_bridge_cap(
    biscuit_bytes: &[u8],
    root_pubkey: &PublicKey,
    ctx: &BridgeVerifyContext,
) -> Result<BridgeFacts, BridgeError> {
    let biscuit = parse(biscuit_bytes, root_pubkey)?;
    // Bridge base tokens do not carry `issued_to`; destination binding is
    // enforced via `dest_pin` in the attenuation block below.
    let plain = verify(
        &biscuit,
        &VerifyContext {
            now_unix_secs: ctx.now_unix_secs,
            local_peer_id: ctx.local_peer_id,
        },
        &ctx.require_capability,
    )?;

    // 1. bridge(true) marker
    if !plain.bridge_marker {
        return Err(BridgeError::AttenuationMissing("bridge(true)"));
    }

    // 2. dest_pin
    let dest_pin = plain
        .dest_pin
        .ok_or(BridgeError::AttenuationMissing("dest_pin"))?;
    if dest_pin != ctx.expected_destination {
        return Err(BridgeError::DestPinMismatch {
            got: dest_pin.to_hex(),
            expected: ctx.expected_destination.to_hex(),
        });
    }

    // 3. rate_limit_bps
    let rate_limit = plain
        .rate_limit_bps
        .ok_or(BridgeError::AttenuationMissing("rate_limit_bps"))?;
    if rate_limit > BRIDGE_RATE_LIMIT_MAX_BPS {
        return Err(BridgeError::RateLimitTooHigh {
            actual: rate_limit,
            max: BRIDGE_RATE_LIMIT_MAX_BPS,
        });
    }

    // 4. total_bytes_cap
    let total_bytes = plain
        .total_bytes_cap
        .ok_or(BridgeError::AttenuationMissing("total_bytes_cap"))?;
    if total_bytes > BRIDGE_TOTAL_BYTES_MAX {
        return Err(BridgeError::TotalBytesTooLarge {
            actual: total_bytes,
            max: BRIDGE_TOTAL_BYTES_MAX,
        });
    }

    // 5. expires (TTL check)
    let expires = plain
        .expires
        .ok_or(BridgeError::AttenuationMissing("expires"))?;
    let ttl = expires - ctx.now_unix_secs;
    if ttl > BRIDGE_TTL_MAX_SECS {
        return Err(BridgeError::TtlTooLong {
            ttl,
            max: BRIDGE_TTL_MAX_SECS,
        });
    }

    Ok(BridgeFacts {
        capabilities: plain.capabilities,
        dest_pin,
        rate_limit_bps: rate_limit,
        total_bytes_cap: total_bytes,
        expires,
    })
}

/// Build a [`ClaimSet`] containing the 5 mandatory bridge attenuation facts.
///
/// Pass the result to [`crate::attenuate_biscuit`] to produce a fully-attenuated
/// bridge cap.
pub fn make_bridge_attenuation(
    dest_peer: PeerId,
    rate_limit_bps: u64,
    total_bytes_cap: u64,
    expires_unix: i64,
) -> ClaimSet {
    ClaimSet::new()
        .dest_pin(dest_peer)
        .rate_limit_bps(rate_limit_bps)
        .total_bytes_cap(total_bytes_cap)
        .expires(expires_unix)
        .bridge_marker()
}
