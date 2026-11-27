//! Bridge cap attenuation rules (spec §6.4).
//!
//! When a node delegates a capability across a transport boundary (e.g.
//! relaying a tier-3 GPU compute cap from a tailscale peer to a LAN peer), the
//! bridge MUST attenuate the original biscuit with five mandatory facts:
//!
//! 1. `dest_pin("<peer-id-hex>")` — the relay only carries traffic for one
//!    specific destination peer.
//! 2. `rate_limit_bps(N)` — max bytes/sec, N <= 1_048_576 (1 MiB/s).
//! 3. `total_bytes_cap(N)` — lifetime byte cap, N <= 1_073_741_824 (1 GiB).
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
    verifier::{authorizer_at, parse, verify_claims, ExtractedFacts, ScopeError, VerifyContext},
};

// ─── Constants ──────────────────────────────────────────────────────────────

/// Maximum TTL for a bridge cap: 1 hour (spec §6.4).
pub const BRIDGE_TTL_MAX_SECS: i64 = 3_600;

/// Maximum rate limit for a bridge cap: 1 MiB/s.
pub const BRIDGE_RATE_LIMIT_MAX_BPS: u64 = 1_048_576;

/// Maximum lifetime byte cap for a bridge cap: 1 GiB.
pub const BRIDGE_TOTAL_BYTES_MAX: u64 = 1_073_741_824;

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
    /// ENTANGLE-E0422: rate_limit_bps exceeds the 1 MiB/s ceiling.
    #[error("ENTANGLE-E0422: bridge rate_limit_bps {actual} exceeds maximum {max}")]
    RateLimitTooHigh {
        /// Actual rate limit in bytes per second.
        actual: u64,
        /// Maximum allowed rate limit in bytes per second.
        max: u64,
    },
    /// ENTANGLE-E0423: total_bytes_cap exceeds the 1 GiB ceiling.
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
    /// Capability surface names granted by the token's **authority block**.
    ///
    /// Appended attenuation blocks cannot add capabilities (the verifier
    /// rejects tokens that try), so this is the complete grant set.
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
    let claims = verify_claims(
        &biscuit,
        &VerifyContext {
            now_unix_secs: ctx.now_unix_secs,
            local_peer_id: ctx.local_peer_id,
        },
        &ctx.require_capability,
        false,
    )
    .map_err(BiscuitError::from)?;
    validate_facts(claims.facts, ctx)
}

fn validate_facts(
    plain: ExtractedFacts,
    ctx: &BridgeVerifyContext,
) -> Result<BridgeFacts, BridgeError> {
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
    let ttl = expires.saturating_sub(ctx.now_unix_secs);
    if ttl > BRIDGE_TTL_MAX_SECS {
        return Err(BridgeError::TtlTooLong {
            ttl,
            max: BRIDGE_TTL_MAX_SECS,
        });
    }

    Ok(BridgeFacts {
        capabilities: plain.authority_capabilities,
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

/// An immutable, authenticated delegation of `mesh.relay` to a particular bridge.
#[derive(Clone)]
pub struct BridgeCap {
    facts: BridgeFacts,
    bridge: PeerId,
    budget_id: Vec<u8>,
    budget_expires: i64,
    issuer: PublicKey,
    token: biscuit_auth::Biscuit,
}

impl std::fmt::Debug for BridgeCap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BridgeCap")
            .field("facts", &self.facts)
            .field("bridge", &self.bridge)
            .finish_non_exhaustive()
    }
}

impl BridgeCap {
    /// Recheck the expiry and signed time-dependent Datalog before receiving a frame.
    pub fn authorize_at(&self, now: i64) -> Result<(), RelayAuthorizationError> {
        if now >= self.facts.expires {
            return Err(RelayAuthorizationError::Expiry);
        }
        authorizer_at(&self.token, Some(now))?
            .authorize()
            .map_err(|e| BiscuitError::Verify(format!("Datalog authorization: {e}")))?;
        Ok(())
    }

    /// Verified destination, bandwidth, lifetime and byte restrictions.
    pub fn facts(&self) -> &BridgeFacts {
        &self.facts
    }
    /// Authority-pinned bridge which must authenticate on the transport.
    pub fn bridge(&self) -> PeerId {
        self.bridge
    }
    /// Verified endpoint signing key.
    pub fn issuer(&self) -> &PublicKey {
        &self.issuer
    }
    /// Stable revocation identifier of the first complete signed delegation.
    pub fn budget_id(&self) -> &[u8] {
        &self.budget_id
    }
    /// Time after which neither this delegation nor its descendants can be used.
    pub fn budget_expires(&self) -> i64 {
        self.budget_expires
    }
}

/// Errors scoped to receiver-side bridge capability verification (§6.4).
#[derive(Debug, thiserror::Error)]
pub enum RelayAuthorizationError {
    /// Missing or excessive rate ceiling.
    #[error("ENTANGLE-E0118: bridge rate limit is missing or exceeds 1 MiB/s")]
    Rate,
    /// Missing or different signed destination.
    #[error("ENTANGLE-E0119: bridge destination is missing or does not match this receiver")]
    Destination,
    /// Missing, elapsed or excessive TTL.
    #[error("ENTANGLE-E0120: bridge expiry is missing, elapsed, or exceeds one hour")]
    Expiry,
    /// Missing bridge marker.
    #[error("ENTANGLE-E0121: bridge marker is missing")]
    Marker,
    /// Missing or excessive lifetime byte ceiling.
    #[error("ENTANGLE-E0122: bridge lifetime byte limit is missing or exceeds 1 GiB")]
    LifetimeBytes,
    /// Signature or signed authorization conditions were rejected.
    #[error(transparent)]
    Biscuit(#[from] BiscuitError),
}

impl From<BridgeError> for RelayAuthorizationError {
    fn from(error: BridgeError) -> Self {
        match error {
            BridgeError::AttenuationMissing("rate_limit_bps")
            | BridgeError::RateLimitTooHigh { .. } => Self::Rate,
            BridgeError::AttenuationMissing("total_bytes_cap")
            | BridgeError::TotalBytesTooLarge { .. } => Self::LifetimeBytes,
            BridgeError::AttenuationMissing("dest_pin") | BridgeError::DestPinMismatch { .. } => {
                Self::Destination
            }
            BridgeError::AttenuationMissing("expires") | BridgeError::TtlTooLong { .. } => {
                Self::Expiry
            }
            BridgeError::AttenuationMissing("bridge(true)") => Self::Marker,
            BridgeError::AttenuationMissing(name) => {
                Self::Biscuit(BiscuitError::MalformedClaim(name.to_owned()))
            }
            BridgeError::Biscuit(e) => Self::Biscuit(e),
        }
    }
}

/// Verify one endpoint's signed relay delegation against its trusted public key,
/// the bridge identity authenticated by the transport, and the local destination.
/// The returned value may be reused by the receiver until expiry.
pub fn verify_bridge(
    token: &[u8],
    trusted_endpoint: &PublicKey,
    authenticated_bridge: PeerId,
    destination: PeerId,
    now_unix_secs: i64,
) -> Result<BridgeCap, RelayAuthorizationError> {
    let biscuit = parse(token, trusted_endpoint)?;
    let claims = verify_claims(
        &biscuit,
        &VerifyContext {
            now_unix_secs,
            local_peer_id: authenticated_bridge,
        },
        "mesh.relay",
        true,
    )
    .map_err(|e| match e {
        ScopeError::Expired { .. } => RelayAuthorizationError::Expiry,
        ScopeError::Biscuit(e) => RelayAuthorizationError::Biscuit(e),
    })?;
    if claims.facts.issued_to != Some(authenticated_bridge) {
        return Err(BiscuitError::Verify(
            "mesh.relay must be issued to the authenticated bridge".into(),
        )
        .into());
    }
    let facts = validate_facts(
        claims.facts,
        &BridgeVerifyContext {
            now_unix_secs,
            local_peer_id: authenticated_bridge,
            expected_destination: destination,
            require_capability: "mesh.relay".into(),
        },
    )?;
    let (index, budget_expires) = claims
        .budget_anchor
        .ok_or_else(|| BiscuitError::Verify("missing signed bridge budget".into()))?;
    let budget_id = biscuit
        .revocation_identifiers()
        .into_iter()
        .nth(index)
        .ok_or_else(|| BiscuitError::Verify("missing signed bridge block identifier".into()))?;
    Ok(BridgeCap {
        facts,
        bridge: authenticated_bridge,
        budget_id,
        budget_expires,
        issuer: *trusted_endpoint,
        token: biscuit,
    })
}

/// Import the paired node's Ed25519 verification key for endpoint relay grants.
pub fn endpoint_key(public: &[u8; 32]) -> Result<PublicKey, BiscuitError> {
    PublicKey::from_bytes(public, biscuit_auth::Algorithm::Ed25519)
        .map_err(|e| BiscuitError::MalformedClaim(e.to_string()))
}

/// Seal a finite relay delegation using this endpoint's PKCS#8 identity.
pub fn mint_relay(
    identity_pem: &str,
    bridge: PeerId,
    destination: PeerId,
    rate: u64,
    total: u64,
    expiry: i64,
    now: i64,
) -> Result<Vec<u8>, RelayAuthorizationError> {
    let key = biscuit_auth::PrivateKey::from_pem(identity_pem)
        .map_err(|e| BiscuitError::Build(e.to_string()))?;
    let authority = crate::mint(
        &key,
        &ClaimSet::new().issued_to(bridge).capability("mesh.relay"),
    )?;
    let att = make_bridge_attenuation(destination, rate, total, expiry);
    let bytes = crate::attenuate_biscuit(&authority, &key.public(), &att)?;
    verify_bridge(&bytes, &key.public(), bridge, destination, now)?;
    parse(&bytes, &key.public())?
        .seal()
        .and_then(|t| t.to_vec())
        .map_err(|e| BiscuitError::Build(e.to_string()).into())
}
