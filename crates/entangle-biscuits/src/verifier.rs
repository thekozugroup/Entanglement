//! Biscuit verification and fact extraction (spec §6).
//!
//! [`verify`] parses a biscuit, checks token-level signature integrity, and
//! extracts the typed [`ExtractedFacts`] by scanning each block's Datalog
//! source individually.
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
//! **Workaround**: rather than driving a `biscuit-auth` `Authorizer`
//! with typed rules (which requires `TryFrom<Fact>` impls per fact arity that
//! are not yet wired up), we re-parse each block's `print_block_source()`
//! text directly. This is robust and avoids the full authorizer machinery.

use biscuit_auth::{Biscuit, PublicKey};
use entangle_types::peer_id::PeerId;

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
    Biscuit::from(bytes, root_pubkey).map_err(|e| BiscuitError::Parse(e.to_string()))
}

/// Extract typed facts from a biscuit, scanning each block individually so
/// that grant-conferring facts are confined to the authority block.
fn extract_facts(biscuit: &Biscuit) -> Result<ExtractedFacts, BiscuitError> {
    let mut facts = ExtractedFacts::default();
    for index in 0..biscuit.block_count() {
        let source = biscuit
            .print_block_source(index)
            .map_err(|e| BiscuitError::Parse(format!("block {index}: {e}")))?;
        scan_block_source(index, &source, &mut facts)?;
    }
    Ok(facts)
}

/// Scan one block's Datalog source for known fact predicates using
/// prefix/suffix matching. Integer terms are parsed directly; string terms
/// are unquoted.
///
/// `index` determines the trust scope: `capability`/`peer` facts are only
/// accepted at [`AUTHORITY_BLOCK_INDEX`]; elsewhere they reject the token.
fn scan_block_source(
    index: usize,
    block_source: &str,
    facts: &mut ExtractedFacts,
) -> Result<(), BiscuitError> {
    for line in block_source.lines() {
        // Block sources emit facts as e.g. `capability("foo");` — trim
        // whitespace, trailing comma, and optional semicolon.
        let line = line.trim().trim_end_matches(',').trim_end_matches(';');

        if let Some(inner) = strip_predicate(line, "peer") {
            if index != AUTHORITY_BLOCK_INDEX {
                return Err(BiscuitError::Verify(format!(
                    "peer fact in non-authority block {index}: \
                     attenuation cannot rebind the issued-to peer"
                )));
            }
            if let Some(hex) = parse_string_term(inner) {
                facts.issued_to = PeerId::from_hex(&hex).ok();
            }
        } else if let Some(inner) = strip_predicate(line, "capability") {
            if index != AUTHORITY_BLOCK_INDEX {
                return Err(BiscuitError::Verify(format!(
                    "capability fact in non-authority block {index}: \
                     attenuation cannot add capabilities"
                )));
            }
            if let Some(s) = parse_string_term(inner) {
                facts.authority_capabilities.push(s);
            }
        } else if let Some(inner) = strip_predicate(line, "expires") {
            if let Ok(n) = inner.trim().parse::<i64>() {
                facts.expires = Some(match facts.expires {
                    None => n,
                    Some(prev) => prev.min(n),
                });
            }
        } else if let Some(inner) = strip_predicate(line, "dest_pin") {
            if let Some(hex) = parse_string_term(inner) {
                let peer = PeerId::from_hex(&hex)
                    .map_err(|e| BiscuitError::MalformedClaim(format!("dest_pin: {e}")))?;
                // First-write-wins: a later block cannot re-pin the destination.
                if facts.dest_pin.is_none() {
                    facts.dest_pin = Some(peer);
                }
            }
        } else if let Some(inner) = strip_predicate(line, "rate_limit_bps") {
            if let Ok(n) = inner.trim().parse::<u64>() {
                facts.rate_limit_bps = Some(match facts.rate_limit_bps {
                    None => n,
                    Some(prev) => prev.min(n),
                });
            }
        } else if let Some(inner) = strip_predicate(line, "total_bytes_cap") {
            if let Ok(n) = inner.trim().parse::<u64>() {
                facts.total_bytes_cap = Some(match facts.total_bytes_cap {
                    None => n,
                    Some(prev) => prev.min(n),
                });
            }
        } else if line == "bridge(true)" {
            facts.bridge_marker = true;
        }
    }

    Ok(())
}

/// Strip `pred(…)` and return the inner text, or `None` if line does not match.
fn strip_predicate<'a>(line: &'a str, pred: &str) -> Option<&'a str> {
    let prefix = format!("{pred}(");
    if line.starts_with(&prefix) && line.ends_with(')') {
        Some(&line[prefix.len()..line.len() - 1])
    } else {
        None
    }
}

/// Parse a quoted string term `"…"` and return the unescaped content.
fn parse_string_term(inner: &str) -> Option<String> {
    let inner = inner.trim();
    if inner.len() >= 2 && inner.starts_with('"') && inner.ends_with('"') {
        let content = &inner[1..inner.len() - 1];
        Some(content.replace("\\\"", "\"").replace("\\\\", "\\"))
    } else {
        None
    }
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
/// 5. Return [`ExtractedFacts`].
pub fn verify(
    biscuit: &Biscuit,
    ctx: &VerifyContext,
    require_capability: &str,
) -> Result<ExtractedFacts, BiscuitError> {
    let facts = extract_facts(biscuit)?;

    // Check 1: expiry — token expired when now >= expires.
    if let Some(exp) = facts.expires {
        if ctx.now_unix_secs >= exp {
            return Err(BiscuitError::Verify(format!(
                "token expired at {exp} (now={now})",
                now = ctx.now_unix_secs
            )));
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
            )));
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
        )));
    }

    Ok(facts)
}
