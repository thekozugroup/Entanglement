//! Biscuit verification and fact extraction (spec §6).
//!
//! [`verify`] parses a biscuit, checks token-level signature integrity, and
//! extracts the typed [`ExtractedFacts`] from each signed block's structured facts.
//!
//! **Trust scoping** (spec §6.4, SECURITY.md): attenuation can only *narrow*
//! a token, never widen it. Grant-conferring facts — `capability(...)` and
//! `peer(...)` — are therefore only honored in the **authority block**
//! (block 0, signed by the root key). Any `capability`/`peer` fact appearing
//! in an appended block (index >= 1) is a widening attempt and causes
//! verification to fail outright. Restriction facts (`expires`, `dest_pin`,
//! `rate_limit_bps`, `total_bytes_cap`, `bridge(true)`) are honored from all
//! blocks and merged so that the *tightest* value wins.
//!
//! Typed fact extraction retains each fact's block of origin. The upstream
//! authorizer separately evaluates every signed Datalog check under Biscuit's
//! normal scope and execution limits.

use biscuit_auth::{
    builder_ext::AuthorizerExt,
    datalog::SymbolTable,
    format::schema::{term::Content, AuthorizerSnapshot},
    Authorizer, AuthorizerBuilder, AuthorizerLimits, Biscuit, DeserializationLimits, PublicKey,
};
use entangle_types::peer_id::PeerId;
use prost::Message;
use std::time::Duration;

use crate::errors::BiscuitError;

/// Index of the authority block — the only block whose facts may confer grants.
const AUTHORITY_BLOCK_INDEX: usize = 0;

// ─── Public context / result types ─────────────────────────────────────────

/// Caller-supplied context for verifying a biscuit.
#[derive(Clone, Debug)]
pub struct VerifyContext {
    /// Unix timestamp (seconds) representing "now". Used for expiry checks.
    pub now_unix_secs: i64,
    /// Identity of the local node accepting the token.
    pub local_peer_id: PeerId,
}

/// Facts extracted from a verified biscuit, split by trust scope.
///
/// Grant-conferring facts ([`authority_capabilities`](Self::authority_capabilities),
/// [`issued_to`](Self::issued_to)) come from the authority block (block 0)
/// ONLY. Restriction facts come from all blocks, merged tightest-wins.
#[derive(Clone, Debug, Default)]
pub struct ExtractedFacts {
    /// `capability("…")` facts found in the **authority block only**.
    ///
    /// A `capability` fact in an appended block (index >= 1) rejects the
    /// token — attenuation cannot add capabilities.
    pub authority_capabilities: Vec<String>,
    /// `peer("…")` — the peer this token was issued to, if present.
    ///
    /// Read from the **authority block only**; a `peer` fact in an appended
    /// block rejects the token — attenuation cannot rebind the holder.
    pub issued_to: Option<PeerId>,
    /// `expires(N)` — the tightest (smallest) expiry across all blocks, if any.
    pub expires: Option<i64>,
    /// `dest_pin("…")` — bridge destination peer, if present.
    ///
    /// First-write-wins across blocks: a later block cannot re-pin the
    /// destination chosen by an earlier block.
    pub dest_pin: Option<PeerId>,
    /// `rate_limit_bps(N)` — the tightest (smallest) bridge rate limit
    /// across all blocks, if present. A later block can only lower it.
    pub rate_limit_bps: Option<u64>,
    /// `total_bytes_cap(N)` — the tightest (smallest) bridge lifetime byte
    /// cap across all blocks, if present. A later block can only lower it.
    pub total_bytes_cap: Option<u64>,
    /// `bridge(true)` — whether the bridge marker fact is present in any block.
    pub bridge_marker: bool,
}

// ─── Internal helpers ───────────────────────────────────────────────────────

/// Parse raw biscuit bytes against `root_pubkey` and return the [`Biscuit`].
pub fn parse(bytes: &[u8], root_pubkey: &PublicKey) -> Result<Biscuit, BiscuitError> {
    let mut limits = DeserializationLimits::allow_everything();
    limits.max_token_size = 256 * 1024;
    limits.max_blocks = 64;
    Biscuit::from_with_limits(bytes, root_pubkey, &limits)
        .map_err(|error| BiscuitError::Parse(error.to_string()))
}

/// The first signed block that completes a relay delegation owns its counter.
/// Further attenuation never creates a fresh budget or extends its retention.
pub(crate) struct VerifiedClaims {
    pub facts: ExtractedFacts,
    pub budget_anchor: Option<(usize, i64)>,
}

fn extract_facts(authorizer: &Authorizer, clock: bool) -> Result<VerifiedClaims, BiscuitError> {
    // The public authorization snapshot preserves source blocks and typed terms.
    // Only read literal facts in those blocks, never derived or ambient facts.
    let bytes = authorizer
        .to_raw_snapshot()
        .map_err(|e| BiscuitError::Parse(e.to_string()))?;
    let world = AuthorizerSnapshot::decode(bytes.as_slice())
        .map_err(|e| BiscuitError::Parse(e.to_string()))?
        .world;
    let symbols =
        SymbolTable::from(world.symbols).map_err(|e| BiscuitError::Parse(e.to_string()))?;
    let mut facts = ExtractedFacts::default();
    let mut budget_anchor = None;
    for (index, block) in world.blocks.iter().enumerate() {
        if clock
            && block
                .rules
                .iter()
                .any(|rule| symbols.get_symbol(rule.head.name) == Some("time"))
        {
            return Err(BiscuitError::Verify(
                "relay clock is supplied by the receiver".into(),
            ));
        }
        for fact in &block.facts {
            let predicate = &fact.predicate;
            let name = symbols
                .get_symbol(predicate.name)
                .ok_or_else(|| BiscuitError::MalformedClaim("unknown predicate".into()))?;
            if clock && name == "time" {
                return Err(BiscuitError::Verify(
                    "relay clock is supplied by the receiver".into(),
                ));
            }
            if !matches!(
                name,
                "peer"
                    | "capability"
                    | "expires"
                    | "dest_pin"
                    | "relay_dest_node"
                    | "rate_limit_bps"
                    | "relay_rate_max"
                    | "total_bytes_cap"
                    | "relay_total_bytes_max"
                    | "bridge"
                    | "bridge_cap"
            ) {
                continue;
            }
            if index != AUTHORITY_BLOCK_INDEX && matches!(name, "peer" | "capability") {
                return Err(BiscuitError::Verify(format!(
                    "{name} fact in non-authority block {index}"
                )));
            }
            let bad = || BiscuitError::MalformedClaim(format!("{name} in block {index}"));
            let [term] = predicate.terms.as_slice() else {
                return Err(bad());
            };
            match (name, term.content.as_ref()) {
                ("capability", Some(Content::String(id))) => {
                    let value = symbols.get_symbol(*id).ok_or_else(bad)?;
                    facts.authority_capabilities.push(value.to_owned());
                }
                ("peer" | "dest_pin" | "relay_dest_node", Some(Content::String(id))) => {
                    let value = symbols.get_symbol(*id).ok_or_else(bad)?;
                    let peer = if let Some(hex_key) = value.strip_prefix("ed25519:") {
                        let key =
                            PublicKey::from_bytes_hex(hex_key, biscuit_auth::Algorithm::Ed25519)
                                .map_err(|_| bad())?;
                        let bytes: [u8; 32] = key.to_bytes().try_into().map_err(|_| bad())?;
                        PeerId::from_public_key_bytes(&bytes)
                    } else {
                        PeerId::from_hex(value).map_err(|_| bad())?
                    };
                    if name == "peer" {
                        if facts
                            .issued_to
                            .replace(peer)
                            .is_some_and(|previous| previous != peer)
                        {
                            return Err(bad());
                        }
                    } else {
                        facts.dest_pin.get_or_insert(peer);
                    }
                }
                ("expires", Some(Content::Integer(n))) => tighten(&mut facts.expires, *n),
                ("expires", Some(Content::Date(n))) => {
                    tighten(&mut facts.expires, i64::try_from(*n).map_err(|_| bad())?)
                }
                ("rate_limit_bps" | "relay_rate_max", Some(Content::Integer(n))) => {
                    tighten(
                        &mut facts.rate_limit_bps,
                        u64::try_from(*n).map_err(|_| bad())?,
                    );
                }
                ("total_bytes_cap" | "relay_total_bytes_max", Some(Content::Integer(n))) => {
                    tighten(
                        &mut facts.total_bytes_cap,
                        u64::try_from(*n).map_err(|_| bad())?,
                    );
                }
                ("bridge" | "bridge_cap", Some(Content::Bool(true))) => facts.bridge_marker = true,
                _ => return Err(bad()),
            }
        }
        if facts.bridge_marker
            && facts.dest_pin.is_some()
            && facts.rate_limit_bps.is_some()
            && facts.total_bytes_cap.is_some()
        {
            if let Some(expiry) = facts.expires {
                budget_anchor.get_or_insert((index, expiry));
            }
        }
    }
    Ok(VerifiedClaims {
        facts,
        budget_anchor,
    })
}

fn tighten<T: Ord + Copy>(slot: &mut Option<T>, value: T) {
    *slot = Some(slot.map_or(value, |old| old.min(value)));
}

// ─── Public API ─────────────────────────────────────────────────────────────

/// Verify a biscuit and extract its typed facts.
///
/// Steps:
/// 1. Parse + signature-check against `root_pubkey` (done by [`parse`]).
/// 2. Extract facts per block; reject `capability`/`peer` facts outside the
///    authority block (attenuation can only narrow, never widen).
/// 3. Ensure `expires` (tightest across all blocks, if present) is in the
///    future.
/// 4. Ensure `require_capability` appears in the **authority** capability
///    list.
/// 5. Enforce the signed Datalog checks, then return [`ExtractedFacts`].
pub fn verify(
    biscuit: &Biscuit,
    ctx: &VerifyContext,
    require_capability: &str,
) -> Result<ExtractedFacts, BiscuitError> {
    verify_claims(biscuit, ctx, require_capability, false)
        .map(|result| result.facts)
        .map_err(Into::into)
}

pub(crate) enum ScopeError {
    Expired { expires: i64, now: i64 },
    Biscuit(BiscuitError),
}

impl From<BiscuitError> for ScopeError {
    fn from(error: BiscuitError) -> Self {
        Self::Biscuit(error)
    }
}

impl From<ScopeError> for BiscuitError {
    fn from(error: ScopeError) -> Self {
        match error {
            ScopeError::Expired { expires, now } => {
                Self::Verify(format!("token expired at {expires} (now={now})"))
            }
            ScopeError::Biscuit(error) => error,
        }
    }
}

pub(crate) fn authorizer_at(
    biscuit: &Biscuit,
    now: Option<i64>,
) -> Result<Authorizer, BiscuitError> {
    let mut builder = AuthorizerBuilder::new()
        .set_limits(AuthorizerLimits {
            max_time: Duration::from_millis(100),
            ..Default::default()
        })
        .allow_all();
    if let Some(now) = now {
        let seconds =
            u64::try_from(now).map_err(|_| BiscuitError::Verify("invalid relay clock".into()))?;
        builder = builder
            .fact(biscuit_auth::builder::Fact::new(
                "time".into(),
                vec![biscuit_auth::builder::Term::Date(seconds)],
            ))
            .map_err(|e| BiscuitError::Verify(e.to_string()))?;
    }
    builder
        .build(biscuit)
        .map_err(|e| BiscuitError::Verify(format!("Datalog authorization: {e}")))
}

pub(crate) fn verify_claims(
    biscuit: &Biscuit,
    ctx: &VerifyContext,
    require_capability: &str,
    clock: bool,
) -> Result<VerifiedClaims, ScopeError> {
    let mut authorizer = authorizer_at(biscuit, clock.then_some(ctx.now_unix_secs))?;
    let verified = extract_facts(&authorizer, clock)?;
    let facts = &verified.facts;

    // Check 1: expiry — token expired when now >= expires.
    if let Some(exp) = facts.expires {
        if ctx.now_unix_secs >= exp {
            return Err(ScopeError::Expired {
                expires: exp,
                now: ctx.now_unix_secs,
            });
        }
    }

    // Check 2: issued_to peer allowlist — if the authority block carries a
    // `peer(P)` claim, P must match local_peer_id (skip if issued_to is
    // absent, e.g. bridge tokens without peer claim). Authority-scoped ONLY:
    // extract_facts has already rejected peer facts in appended blocks.
    if let Some(ref issued) = facts.issued_to {
        if *issued != ctx.local_peer_id {
            return Err(BiscuitError::Verify(format!(
                "token issued to peer {} but local peer is {}",
                issued.to_hex(),
                ctx.local_peer_id.to_hex()
            ))
            .into());
        }
    }

    // Check 3: required capability must be granted by the authority block.
    if !facts
        .authority_capabilities
        .iter()
        .any(|c| c == require_capability)
    {
        return Err(BiscuitError::Verify(format!(
            "required capability '{require_capability}' not present in authority block"
        ))
        .into());
    }

    // The typed grant and restrictions above establish our allow policy.
    // Biscuit checks can narrow it further. Only token facts are available
    // to these checks; unsupported ambient predicates fail closed.
    authorizer
        .authorize()
        .map_err(|error| BiscuitError::Verify(format!("Datalog authorization: {error}")))?;
    Ok(verified)
}
