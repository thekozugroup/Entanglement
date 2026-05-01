//! Biscuit verification and fact extraction (spec §6).
//!
//! [`verify`] parses a biscuit, checks token-level signature integrity, and
//! extracts the typed [`ExtractedFacts`] by scanning the token's Datalog text
//! representation.
//!
//! **Workaround**: rather than driving a `biscuit-auth` `Authorizer`
//! with typed rules (which requires `TryFrom<Fact>` impls per fact arity that
//! are not yet wired up), we re-parse the token's `.print()` text
//! directly. This is robust and avoids the full authorizer machinery.

use biscuit_auth::{Biscuit, PublicKey};
use entangle_types::peer_id::PeerId;

use crate::errors::BiscuitError;

// ─── Public context / result types ─────────────────────────────────────────

/// Caller-supplied context for verifying a biscuit.
#[derive(Clone, Debug)]
pub struct VerifyContext {
    /// Unix timestamp (seconds) representing "now". Used for expiry checks.
    pub now_unix_secs: i64,
    /// Identity of the local node accepting the token.
    pub local_peer_id: PeerId,
}

/// Facts extracted from a verified biscuit.
#[derive(Clone, Debug, Default)]
pub struct ExtractedFacts {
    /// All `capability("…")` facts found across all blocks.
    pub capabilities: Vec<String>,
    /// `peer("…")` — the peer this token was issued to, if present.
    pub issued_to: Option<PeerId>,
    /// `expires(N)` — the tightest (smallest) expiry found, if any.
    pub expires: Option<i64>,
    /// `dest_pin("…")` — bridge destination peer, if present.
    pub dest_pin: Option<PeerId>,
    /// `rate_limit_bps(N)` — bridge rate limit, if present.
    pub rate_limit_bps: Option<u64>,
    /// `total_bytes_cap(N)` — bridge lifetime byte cap, if present.
    pub total_bytes_cap: Option<u64>,
    /// `bridge(true)` — whether the bridge marker fact is present.
    pub bridge_marker: bool,
}

// ─── Internal helpers ───────────────────────────────────────────────────────

/// Parse raw biscuit bytes against `root_pubkey` and return the [`Biscuit`].
pub fn parse(bytes: &[u8], root_pubkey: &PublicKey) -> Result<Biscuit, BiscuitError> {
    Biscuit::from(bytes, root_pubkey).map_err(|e| BiscuitError::Parse(e.to_string()))
}

/// Extract typed facts from the Datalog text of all blocks.
///
/// `biscuit_auth::Biscuit::print()` emits the complete Datalog source for all
/// blocks. We scan this text for known fact predicates using prefix/suffix
/// matching. Integer terms are parsed directly; string terms are unquoted.
fn extract_facts_from_text(datalog_text: &str) -> Result<ExtractedFacts, BiscuitError> {
    let mut facts = ExtractedFacts::default();

    for line in datalog_text.lines() {
        // biscuit.print() emits facts as:
        //   `                capability("foo"),`
        // Trim whitespace, trailing comma, and optional semicolon.
        let line = line.trim().trim_end_matches(',').trim_end_matches(';');

        if let Some(inner) = strip_predicate(line, "peer") {
            if let Some(hex) = parse_string_term(inner) {
                facts.issued_to = PeerId::from_hex(&hex).ok();
            }
        } else if let Some(inner) = strip_predicate(line, "capability") {
            if let Some(s) = parse_string_term(inner) {
                facts.capabilities.push(s);
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
                facts.dest_pin = Some(peer);
            }
        } else if let Some(inner) = strip_predicate(line, "rate_limit_bps") {
            if let Ok(n) = inner.trim().parse::<u64>() {
                facts.rate_limit_bps = Some(n);
            }
        } else if let Some(inner) = strip_predicate(line, "total_bytes_cap") {
            if let Ok(n) = inner.trim().parse::<u64>() {
                facts.total_bytes_cap = Some(n);
            }
        } else if line == "bridge(true)" {
            facts.bridge_marker = true;
        }
    }

    Ok(facts)
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
/// 1. Parse + signature-check against `root_pubkey`.
/// 2. Ensure `expires` (if present) is in the future.
/// 3. Ensure `require_capability` appears in the capability list.
/// 4. Return [`ExtractedFacts`].
pub fn verify(
    biscuit: &Biscuit,
    ctx: &VerifyContext,
    require_capability: &str,
) -> Result<ExtractedFacts, BiscuitError> {
    let datalog_text = biscuit.print();
    let facts = extract_facts_from_text(&datalog_text)?;

    // Check 1: expiry — token expired when now >= expires.
    if let Some(exp) = facts.expires {
        if ctx.now_unix_secs >= exp {
            return Err(BiscuitError::Verify(format!(
                "token expired at {exp} (now={now})",
                now = ctx.now_unix_secs
            )));
        }
    }

    // Check 2: issued_to peer allowlist — if a `peer(P)` claim is present, P must match
    // local_peer_id (skip if issued_to is absent, e.g. bridge tokens without peer claim).
    if let Some(ref issued) = facts.issued_to {
        if *issued != ctx.local_peer_id {
            return Err(BiscuitError::Verify(format!(
                "token issued to peer {} but local peer is {}",
                issued.to_hex(),
                ctx.local_peer_id.to_hex()
            )));
        }
    }

    // Check 3: required capability must be present.
    if !facts.capabilities.iter().any(|c| c == require_capability) {
        return Err(BiscuitError::Verify(format!(
            "required capability '{require_capability}' not present"
        )));
    }

    Ok(facts)
}
