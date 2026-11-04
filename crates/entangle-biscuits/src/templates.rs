//! Curated capability templates (spec §6.6) and the per-request token
//! protocol that gates remote work (spec §6.1.1, §6.3 step 4, §7.4, §13 #8).
//!
//! Plugin authors and the daemon compose these instead of writing Datalog.
//! Every template is plain facts — no rules, no checks — so a token can be
//! read, and verified, by scanning its blocks.
//!
//! | Template | Shape | Lifetime | Consumed by |
//! |---|---|---|---|
//! | [`MESH_PEER`] | authority block: `peer("<holder>")`, `capability("mesh.peer")`, optional `expires(T)`; rooted at the **issuer's** identity key | long-lived: until revoked | every `entangle/scheduler/1` task and `entangle/stream/1` `Open` ([`verify_request`]) |
//! | [`COMPUTE_GPU_JOB`] | a `mesh.peer` token plus an attenuation block `gpu_job(true)` and an optional `expires(T)` | the issuer's choice | nothing yet: a task frame carries no resource spec, so a worker cannot tell a GPU task from another and refuses the restriction ([`TokenError::RestrictionNotMet`]) |
//! | [`AGENT_SESSION`] | a `mesh.peer` token plus `agent_session("<id>")` and a required `expires(T)` at most [`AGENT_SESSION_MAX_TTL_SECS`] away | short | nothing yet: there is no `entangle/agent/1` server |
//!
//! # Who mints what
//!
//! A `mesh.peer` token is minted by the node that will **verify** it, rooted
//! at that node's own identity key and issued to the peer that will
//! **present** it ([`mint_mesh_peer`]). Pairing exchanges one in each
//! direction. Nobody but the issuer can mint a token its verifier accepts,
//! and only the holder named in it can use it: the verifier compares the
//! `peer` fact with the identity the transport authenticated.
//!
//! # Per-request presentation
//!
//! The holder never sends the long-lived token as-is. For every request it
//! appends one attenuation block ([`present_for_request`]):
//!
//! * `expires(now + 60)` ([`REQUEST_TOKEN_TTL_SECS`]),
//! * `nonce("<16 random bytes, hex>")`,
//! * `request_binding("<32-byte digest of the request, hex>")` — the caller
//!   decides what the digest covers (the scheduler binds the task id,
//!   plugin, input digest and policy hash).
//!
//! The verifier ([`verify_request`], [`RequestVerifier`]) then requires, in
//! this order: the token parses and its signature chain verifies under the
//! verifier's **own** public key; every block holds only facts this module
//! defines (grant facts only in the authority block); the `peer` fact names
//! the presenter; `capability("mesh.peer")` is granted; the tightest
//! `expires` exists, has not passed — give or take the late-arrival grace
//! of a large frame ([`late_arrival_grace_secs`]) — and is no more than
//! [`REQUEST_TOKEN_TTL_SECS`] + [`MAX_CLOCK_SKEW_SECS`] away; every
//! `request_binding` equals the request's digest; there is exactly one
//! nonce; every template restriction in the chain is satisfied by the
//! operation; no revocation id of the token is in the local revocation set;
//! and the nonce has not been seen ([`ReplayCache`]).
//!
//! # When a presenter attenuates, and late arrival
//!
//! A presenter attenuates once per attempt to send, once the connection is
//! set up and immediately before the frame is written, so time spent
//! dialling — including falling back from one transport to another — never
//! counts against the token's 60 s. A resend is a new attenuation with a
//! new nonce. What remains is the time the frame itself takes to arrive:
//! a verifier sees a token only once the whole frame is in, so a large
//! frame on a slow link earns one second of grace per 256 KiB received
//! ([`late_arrival_grace_secs`], capped at [`MAX_LATE_ARRIVAL_GRACE_SECS`]),
//! and the replay cache remembers its nonce for that much longer.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};

use biscuit_auth::builder::{Algorithm, BlockBuilder};
use biscuit_auth::{Biscuit, KeyPair, PrivateKey, PublicKey, UnverifiedBiscuit};
use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;

// ─── Names and limits ───────────────────────────────────────────────────────

/// The `mesh.peer` template and the capability it grants: "this peer may ask
/// the issuer to do work" (spec §6.3 step 4).
pub const MESH_PEER: &str = "mesh.peer";
/// The `compute.gpu-job` template: a `mesh.peer` token restricted to tasks
/// that request a GPU.
pub const COMPUTE_GPU_JOB: &str = "compute.gpu-job";
/// The `agent.session` template: a `mesh.peer` token bound to one agent
/// session id, with a short expiry.
pub const AGENT_SESSION: &str = "agent.session";

/// How far ahead a presenter sets the expiry of a per-request token (spec
/// §13 #8: "60s expiry").
pub const REQUEST_TOKEN_TTL_SECS: i64 = 60;
/// Clock difference between presenter and verifier that the verifier
/// tolerates on top of [`REQUEST_TOKEN_TTL_SECS`]: a per-request token may
/// expire at most `60 + 30` seconds after the verifier's "now".
pub const MAX_CLOCK_SKEW_SECS: i64 = 30;
/// Longest expiry an `agent.session` attenuation may carry.
pub const AGENT_SESSION_MAX_TTL_SECS: i64 = 3_600;
/// Largest token a verifier parses. A `mesh.peer` token plus one
/// per-request block is about 500 bytes.
pub const MAX_TOKEN_BYTES: usize = 4_096;
/// Length of a per-request nonce, in bytes.
pub const NONCE_LEN: usize = 16;
/// Longest agent session id ([`attenuate_agent_session`]).
pub const MAX_SESSION_ID_LEN: usize = 128;

/// Bytes of the received frame that earn a per-request token one second of
/// late-arrival grace ([`late_arrival_grace_secs`]): 256 KiB, what a link
/// of 2 Mbit/s delivers in a second.
pub const LATE_ARRIVAL_BYTES_PER_SEC: usize = 262_144;
/// The most late-arrival grace any frame earns, however large it is. A
/// scheduler task frame is at most 16 MiB + 64 KiB (64 s of grace), so this
/// only bounds transports or configurations with larger frames.
pub const MAX_LATE_ARRIVAL_GRACE_SECS: i64 = 600;

/// Default number of nonces a [`ReplayCache`] tracks at once.
pub const DEFAULT_REPLAY_CAPACITY: usize = 65_536;
/// Default number of nonces one presenter may hold in a [`ReplayCache`] at
/// once, so one peer cannot fill the cache for everybody.
pub const DEFAULT_REPLAY_PER_PEER: usize = 16_384;
/// How long after its token stops being accepted (its expiry plus the
/// frame's late-arrival grace) a nonce is still remembered: covers a
/// verifier clock that steps backwards by up to [`MAX_CLOCK_SKEW_SECS`].
pub const REPLAY_GRACE_SECS: i64 = 30;

// A replay must stay refused for as long as any clock the verifier
// tolerates could still accept its token.
const _: () = assert!(REPLAY_GRACE_SECS >= MAX_CLOCK_SKEW_SECS);

/// The late-arrival grace, in seconds, that a per-request token earns from
/// the frame that carried it: `received_frame_len /`
/// [`LATE_ARRIVAL_BYTES_PER_SEC`] (integer division, so a frame under
/// 256 KiB earns none), at most [`MAX_LATE_ARRIVAL_GRACE_SECS`].
///
/// A verifier checks a token's expiry only once the whole frame carrying it
/// has arrived, and a large input on a slow link can take longer than the
/// token's [`REQUEST_TOKEN_TTL_SECS`] to arrive. Such a token counts as
/// expired only once `now >= expires + grace`. The grace scales with the
/// frame and only with it: `received_frame_len` must be the length the
/// transport actually received, never a length the presenter declares. How
/// far ahead a token may expire is unchanged
/// ([`TokenError::ExpiryOutOfWindow`]).
pub const fn late_arrival_grace_secs(received_frame_len: usize) -> i64 {
    let secs = received_frame_len / LATE_ARRIVAL_BYTES_PER_SEC;
    if secs >= MAX_LATE_ARRIVAL_GRACE_SECS as usize {
        MAX_LATE_ARRIVAL_GRACE_SECS
    } else {
        // Below the cap (600), so the cast is exact.
        secs as i64
    }
}

// ─── Errors ─────────────────────────────────────────────────────────────────

/// Why a capability token was not minted, presented or accepted.
///
/// E0411 and E0412 are shared with [`crate::BiscuitError`] on purpose: they
/// mean exactly the same thing there (a build failure; an expired token).
/// The remote-token range is E0450–E0469.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TokenError {
    /// ENTANGLE-E0411: minting or attenuating a token failed.
    #[error("ENTANGLE-E0411: build: {0}")]
    Build(String),
    /// ENTANGLE-E0412: the token's tightest expiry has passed.
    #[error("ENTANGLE-E0412: verify failed: token expired at {expires} (now={now})")]
    Expired {
        /// The tightest `expires` across the token's blocks.
        expires: i64,
        /// The verifier's clock.
        now: i64,
    },
    /// ENTANGLE-E0450: the request carries no token and this node requires
    /// one.
    #[error(
        "ENTANGLE-E0450: the request carries no capability token and this node requires one \
         ([trust] require_capability_tokens = true); re-pair with `entangle pair` so both \
         nodes hold a mesh.peer token"
    )]
    Missing,
    /// ENTANGLE-E0451: the bytes are not a biscuit, or are too large.
    #[error("ENTANGLE-E0451: capability token is malformed: {0}")]
    Malformed(String),
    /// ENTANGLE-E0452: the signature chain does not verify under the
    /// expected root key (another node minted it, or it was altered).
    #[error(
        "ENTANGLE-E0452: capability token does not verify against the expected identity key \
         (minted by another node, or altered): {0}"
    )]
    BadSignature(String),
    /// ENTANGLE-E0453: the token names another holder than the peer that
    /// presented it.
    #[error(
        "ENTANGLE-E0453: capability token was issued to peer {issued_to}, but presented by \
         peer {presenter}"
    )]
    WrongHolder {
        /// The `peer` fact of the authority block (`none` when absent).
        issued_to: String,
        /// The transport-authenticated presenter.
        presenter: String,
    },
    /// ENTANGLE-E0454: the authority block does not grant the capability.
    #[error("ENTANGLE-E0454: capability token does not grant `{0}`")]
    CapabilityNotGranted(String),
    /// ENTANGLE-E0455: a per-request token without an expiry, or with one
    /// too far ahead.
    #[error(
        "ENTANGLE-E0455: per-request capability token must expire within {max_secs}s: {detail}"
    )]
    ExpiryOutOfWindow {
        /// The longest accepted distance, [`REQUEST_TOKEN_TTL_SECS`] +
        /// [`MAX_CLOCK_SKEW_SECS`].
        max_secs: i64,
        /// What was wrong.
        detail: String,
    },
    /// ENTANGLE-E0456: the token is bound to another request (or to none).
    #[error("ENTANGLE-E0456: capability token is not bound to this request: {0}")]
    BindingMismatch(String),
    /// ENTANGLE-E0457: the token does not carry exactly one well-formed nonce.
    #[error("ENTANGLE-E0457: capability token must carry exactly one {NONCE_LEN}-byte nonce: {0}")]
    BadNonce(String),
    /// ENTANGLE-E0458: the nonce was already used: a replayed request.
    #[error("ENTANGLE-E0458: capability token nonce was already used (replayed request)")]
    Replayed,
    /// ENTANGLE-E0459: the replay cache is full; the request is refused
    /// rather than accepted unchecked.
    #[error("ENTANGLE-E0459: too many recent capability tokens to track replays ({0}); refused, retry shortly")]
    ReplayCacheFull(String),
    /// ENTANGLE-E0460: a revocation id of the token is in the local
    /// revocation set.
    #[error(
        "ENTANGLE-E0460: capability token has been revoked on this node (`entangle peers \
         remove`); re-pair with `entangle pair`"
    )]
    Revoked,
    /// ENTANGLE-E0461: a block holds something other than this module's
    /// facts (a rule, a check, an unknown fact, a grant fact outside the
    /// authority block, a duplicate holder).
    #[error("ENTANGLE-E0461: capability token contains content this node does not accept: {0}")]
    UnexpectedContent(String),
    /// ENTANGLE-E0462: a template restriction in the token (`gpu_job`,
    /// `agent_session`) is not satisfied by the operation.
    #[error("ENTANGLE-E0462: capability token restriction not satisfied by this request: {0}")]
    RestrictionNotMet(String),
    /// ENTANGLE-E0463: the local revocation set could not be read, so no
    /// token is accepted (fail closed).
    #[error("ENTANGLE-E0463: the local revocation set could not be read, so no capability token is accepted: {0}")]
    RevocationsUnavailable(String),
}

impl TokenError {
    /// A short, stable label for metrics (a fixed set: bounded cardinality).
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Build(_) => "build",
            Self::Expired { .. } => "expired",
            Self::Missing => "missing",
            Self::Malformed(_) => "malformed",
            Self::BadSignature(_) => "bad_signature",
            Self::WrongHolder { .. } => "wrong_holder",
            Self::CapabilityNotGranted(_) => "capability_not_granted",
            Self::ExpiryOutOfWindow { .. } => "expiry_out_of_window",
            Self::BindingMismatch(_) => "binding_mismatch",
            Self::BadNonce(_) => "bad_nonce",
            Self::Replayed => "replayed",
            Self::ReplayCacheFull(_) => "replay_cache_full",
            Self::Revoked => "revoked",
            Self::UnexpectedContent(_) => "unexpected_content",
            Self::RestrictionNotMet(_) => "restriction_not_met",
            Self::RevocationsUnavailable(_) => "revocations_unavailable",
        }
    }

    /// Every [`TokenError::label`], for documentation and metric tests.
    pub const LABELS: [&'static str; 16] = [
        "build",
        "expired",
        "missing",
        "malformed",
        "bad_signature",
        "wrong_holder",
        "capability_not_granted",
        "expiry_out_of_window",
        "binding_mismatch",
        "bad_nonce",
        "replayed",
        "replay_cache_full",
        "revoked",
        "unexpected_content",
        "restriction_not_met",
        "revocations_unavailable",
    ];
}

// ─── Keys ───────────────────────────────────────────────────────────────────

/// The biscuit root key pair of an Entanglement identity: the same Ed25519
/// key, so a token rooted at it verifies under the node's public key (the
/// key its `PeerId` is derived from).
pub fn root_keypair(identity: &IdentityKeyPair) -> Result<KeyPair, TokenError> {
    // `IdentityKeyPair` deliberately does not expose its secret bytes; PKCS#8
    // PEM is the one serialization it offers, so round-trip through it (as
    // `entangle-mesh-iroh` does for its endpoint key). The seed is wiped as
    // soon as biscuit-auth holds its own copy.
    use ed25519_dalek::pkcs8::DecodePrivateKey as _;
    let pem = zeroize::Zeroizing::new(identity.to_pem());
    let signing = ed25519_dalek::SigningKey::from_pkcs8_pem(&pem)
        .map_err(|e| TokenError::Build(format!("identity key is not PKCS#8: {e}")))?;
    let seed = zeroize::Zeroizing::new(signing.to_bytes());
    let private = PrivateKey::from_bytes(seed.as_slice(), Algorithm::Ed25519)
        .map_err(|e| TokenError::Build(format!("identity key: {e}")))?;
    Ok(KeyPair::from(&private))
}

/// A raw 32-byte Ed25519 public key as a biscuit root key.
pub fn root_public_key(raw: &[u8; 32]) -> Result<PublicKey, TokenError> {
    PublicKey::from_bytes(raw, Algorithm::Ed25519)
        .map_err(|e| TokenError::BadSignature(format!("root key is not an Ed25519 point: {e}")))
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

// ─── Minting and attenuating ────────────────────────────────────────────────

/// A freshly minted token and what its issuer needs to revoke it later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintedToken {
    /// The serialized biscuit, to hand to the holder.
    pub bytes: Vec<u8>,
    /// Its revocation ids (one per block; a fresh token has one). Revoking
    /// the authority block's id revokes every attenuation of the token.
    pub revocation_ids: Vec<Vec<u8>>,
}

/// Mint a `mesh.peer` token rooted at `issuer`'s identity key and issued to
/// `holder`, optionally expiring at `expires` (Unix seconds). Pairing mints
/// one without expiry: it lives until revoked.
pub fn mint_mesh_peer(
    issuer: &IdentityKeyPair,
    holder: PeerId,
    expires: Option<i64>,
) -> Result<MintedToken, TokenError> {
    let root = root_keypair(issuer)?;
    let mut builder = Biscuit::builder()
        .fact(format!("peer(\"{}\")", holder.to_hex()).as_str())
        .and_then(|b| b.fact(format!("capability(\"{MESH_PEER}\")").as_str()))
        .map_err(|e| TokenError::Build(e.to_string()))?;
    if let Some(t) = expires {
        builder = builder
            .fact(format!("expires({t})").as_str())
            .map_err(|e| TokenError::Build(e.to_string()))?;
    }
    let biscuit = builder
        .build(&root)
        .map_err(|e| TokenError::Build(e.to_string()))?;
    Ok(MintedToken {
        bytes: biscuit
            .to_vec()
            .map_err(|e| TokenError::Build(e.to_string()))?,
        revocation_ids: biscuit.revocation_identifiers(),
    })
}

/// Parse `token` under the issuer's key, append `facts` as one block.
fn append_block(
    token: &[u8],
    issuer_public_key: &[u8; 32],
    facts: &[String],
) -> Result<Vec<u8>, TokenError> {
    let biscuit = parse_under(token, &root_public_key(issuer_public_key)?)?;
    let mut block = BlockBuilder::new();
    for fact in facts {
        block = block
            .fact(fact.as_str())
            .map_err(|e| TokenError::Build(e.to_string()))?;
    }
    biscuit
        .append(block)
        .and_then(|b| b.to_vec())
        .map_err(|e| TokenError::Build(e.to_string()))
}

/// The `compute.gpu-job` template: restrict a `mesh.peer` token (rooted at
/// `issuer_public_key`) to tasks that request a GPU, optionally until
/// `expires`.
pub fn attenuate_gpu_job(
    token: &[u8],
    issuer_public_key: &[u8; 32],
    expires: Option<i64>,
) -> Result<Vec<u8>, TokenError> {
    let mut facts = vec!["gpu_job(true)".to_owned()];
    if let Some(t) = expires {
        facts.push(format!("expires({t})"));
    }
    append_block(token, issuer_public_key, &facts)
}

/// The `agent.session` template: bind a `mesh.peer` token (rooted at
/// `issuer_public_key`) to one agent session until `expires`, which must be
/// in the future and at most [`AGENT_SESSION_MAX_TTL_SECS`] after `now`.
///
/// A session id is 1..=[`MAX_SESSION_ID_LEN`] characters of
/// `[A-Za-z0-9._-]`, so it never needs escaping inside Datalog.
pub fn attenuate_agent_session(
    token: &[u8],
    issuer_public_key: &[u8; 32],
    session_id: &str,
    expires: i64,
    now: i64,
) -> Result<Vec<u8>, TokenError> {
    check_session_id(session_id).map_err(TokenError::Build)?;
    if expires <= now || expires - now > AGENT_SESSION_MAX_TTL_SECS {
        return Err(TokenError::Build(format!(
            "an agent.session token must expire within {AGENT_SESSION_MAX_TTL_SECS}s \
             (expires {expires}, now {now})"
        )));
    }
    append_block(
        token,
        issuer_public_key,
        &[
            format!("agent_session(\"{session_id}\")"),
            format!("expires({expires})"),
        ],
    )
}

fn check_session_id(id: &str) -> Result<(), String> {
    let ok = !id.is_empty()
        && id.len() <= MAX_SESSION_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "agent session id must be 1..={MAX_SESSION_ID_LEN} characters of [A-Za-z0-9._-]"
        ))
    }
}

/// What a per-request attenuation block says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestRestrictions {
    /// Absolute expiry, Unix seconds.
    pub expires: i64,
    /// A value never used before by this presenter.
    pub nonce: [u8; NONCE_LEN],
    /// Digest of the request this token may authorise.
    pub binding: [u8; 32],
}

/// Append a per-request block to `token` (rooted at `issuer_public_key`).
///
/// [`present_for_request`] is what a presenter calls; this lower-level form
/// lets tests build tokens with any expiry, nonce or binding.
pub fn attenuate_for_request(
    token: &[u8],
    issuer_public_key: &[u8; 32],
    restrictions: &RequestRestrictions,
) -> Result<Vec<u8>, TokenError> {
    append_block(
        token,
        issuer_public_key,
        &[
            format!("expires({})", restrictions.expires),
            format!("nonce(\"{}\")", hex::encode(restrictions.nonce)),
            format!("request_binding(\"{}\")", hex::encode(restrictions.binding)),
        ],
    )
}

/// Attenuate the stored `token` (rooted at `issuer_public_key`, the
/// verifier's key) for one request: a fresh random nonce, `binding`, and an
/// expiry [`REQUEST_TOKEN_TTL_SECS`] after `now`.
pub fn present_for_request(
    token: &[u8],
    issuer_public_key: &[u8; 32],
    binding: [u8; 32],
    now: i64,
) -> Result<Vec<u8>, TokenError> {
    use rand_core::{OsRng, RngCore as _};
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    attenuate_for_request(
        token,
        issuer_public_key,
        &RequestRestrictions {
            expires: now.saturating_add(REQUEST_TOKEN_TTL_SECS),
            nonce,
            binding,
        },
    )
}

// ─── Scanning ───────────────────────────────────────────────────────────────

/// Parse `token` and verify its signature chain under `root`, telling a
/// malformed token from one that verifies under another key.
fn parse_under(token: &[u8], root: &PublicKey) -> Result<Biscuit, TokenError> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(TokenError::Malformed(format!(
            "{} bytes exceeds the {MAX_TOKEN_BYTES}-byte cap",
            token.len()
        )));
    }
    UnverifiedBiscuit::from(token).map_err(|e| TokenError::Malformed(e.to_string()))?;
    Biscuit::from(token, *root).map_err(|e| TokenError::BadSignature(e.to_string()))
}

/// Everything the template facts of a token say, read strictly.
#[derive(Debug, Default)]
struct Scanned {
    blocks: usize,
    issued_to: Option<PeerId>,
    capabilities: Vec<String>,
    expires: Option<i64>,
    nonces: Vec<String>,
    bindings: Vec<String>,
    gpu_job: bool,
    agent_sessions: Vec<String>,
}

/// Read every block's facts. Anything but a template fact — a rule, a check,
/// an unknown predicate, a grant fact (`peer`, `capability`) outside the
/// authority block, a restriction fact inside it, a second `peer` — rejects
/// the token: a verifier that skipped what it does not understand could be
/// made to skip a restriction.
fn scan(biscuit: &Biscuit) -> Result<Scanned, TokenError> {
    let mut s = Scanned {
        blocks: biscuit.block_count(),
        ..Scanned::default()
    };
    for index in 0..s.blocks {
        let source = biscuit
            .print_block_source(index)
            .map_err(|e| TokenError::Malformed(format!("block {index}: {e}")))?;
        let authority = index == 0;
        for raw in source.lines() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            let unexpected = || TokenError::UnexpectedContent(format!("block {index}: `{line}`"));
            let (name, arg) = split_fact(line).ok_or_else(unexpected)?;
            match (authority, name) {
                (true, "peer") => {
                    let hex = string_term(arg).ok_or_else(unexpected)?;
                    let peer = PeerId::from_hex(hex).map_err(|_| unexpected())?;
                    if s.issued_to.replace(peer).is_some() {
                        return Err(unexpected());
                    }
                }
                (true, "capability") => {
                    s.capabilities
                        .push(string_term(arg).ok_or_else(unexpected)?.to_owned());
                }
                (_, "expires") => {
                    let t: i64 = arg.parse().map_err(|_| unexpected())?;
                    s.expires = Some(s.expires.map_or(t, |prev| prev.min(t)));
                }
                (false, "nonce") => s
                    .nonces
                    .push(string_term(arg).ok_or_else(unexpected)?.to_owned()),
                (false, "request_binding") => s
                    .bindings
                    .push(string_term(arg).ok_or_else(unexpected)?.to_owned()),
                (false, "gpu_job") if arg == "true" => s.gpu_job = true,
                (false, "agent_session") => s
                    .agent_sessions
                    .push(string_term(arg).ok_or_else(unexpected)?.to_owned()),
                _ => return Err(unexpected()),
            }
        }
    }
    Ok(s)
}

/// `name(arg);` → `(name, arg)`, where `name` is `[a-z_]+` and `arg` holds
/// no parenthesis, comma or semicolon (one term, no rule, no check).
fn split_fact(line: &str) -> Option<(&str, &str)> {
    let body = line.strip_suffix(';')?;
    let open = body.find('(')?;
    let name = &body[..open];
    let arg = body[open + 1..].strip_suffix(')')?;
    let name_ok = !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
    let arg_ok = !arg.is_empty() && !arg.contains(['(', ')', ',', ';']);
    (name_ok && arg_ok).then_some((name, arg))
}

/// `"text"` → `text`, refusing escapes and embedded quotes (no template
/// value needs them).
fn string_term(arg: &str) -> Option<&str> {
    let inner = arg.strip_prefix('"')?.strip_suffix('"')?;
    (!inner.contains(['"', '\\'])).then_some(inner)
}

/// The checks every template shares: parse under `root`, scan strictly, the
/// holder is `holder`, `mesh.peer` is granted, not expired — where a token
/// counts as expired once `now >= expires + late_grace` (`late_grace` is 0
/// everywhere but for a per-request token in a large frame:
/// [`late_arrival_grace_secs`]).
fn verify_chain(
    token: &[u8],
    root: &PublicKey,
    holder: PeerId,
    now: i64,
    late_grace: i64,
) -> Result<(Scanned, Vec<Vec<u8>>), TokenError> {
    let biscuit = parse_under(token, root)?;
    let scanned = scan(&biscuit)?;
    match scanned.issued_to {
        Some(p) if p == holder => {}
        other => {
            return Err(TokenError::WrongHolder {
                issued_to: other.map_or_else(|| "none".to_owned(), |p| p.to_hex()),
                presenter: holder.to_hex(),
            })
        }
    }
    if !scanned.capabilities.iter().any(|c| c == MESH_PEER) {
        return Err(TokenError::CapabilityNotGranted(MESH_PEER.to_owned()));
    }
    if let Some(expires) = scanned.expires {
        if now >= expires.saturating_add(late_grace) {
            return Err(TokenError::Expired { expires, now });
        }
    }
    Ok((scanned, biscuit.revocation_identifiers()))
}

// ─── Verifying long-lived grants ────────────────────────────────────────────

/// What a verified template token grants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateGrant {
    /// The holder named in the authority block.
    pub holder: PeerId,
    /// The tightest expiry, if the token has one.
    pub expires: Option<i64>,
    /// The token's revocation ids, authority block first.
    pub revocation_ids: Vec<Vec<u8>>,
}

/// Check a `mesh.peer` token received while pairing: it verifies under the
/// issuer's key, has exactly one (authority) block, is issued to `holder`
/// (this node), grants `mesh.peer`, and has not expired.
pub fn verify_mesh_peer_grant(
    token: &[u8],
    issuer_public_key: &[u8; 32],
    holder: PeerId,
    now: i64,
) -> Result<TemplateGrant, TokenError> {
    let (scanned, revocation_ids) =
        verify_chain(token, &root_public_key(issuer_public_key)?, holder, now, 0)?;
    if scanned.blocks != 1 {
        return Err(TokenError::UnexpectedContent(format!(
            "a mesh.peer grant has exactly one block, this token has {}",
            scanned.blocks
        )));
    }
    Ok(TemplateGrant {
        holder,
        expires: scanned.expires,
        revocation_ids,
    })
}

/// Check a `compute.gpu-job` token presented by `holder`: a valid `mesh.peer`
/// chain under `root` carrying the `gpu_job` restriction, used for a task
/// that requests a GPU (`task_requests_gpu`).
pub fn verify_gpu_job(
    token: &[u8],
    root: &PublicKey,
    holder: PeerId,
    now: i64,
    task_requests_gpu: bool,
) -> Result<TemplateGrant, TokenError> {
    let (scanned, revocation_ids) = verify_chain(token, root, holder, now, 0)?;
    if !scanned.gpu_job {
        return Err(TokenError::CapabilityNotGranted(COMPUTE_GPU_JOB.to_owned()));
    }
    check_restrictions(
        &scanned,
        Operation::Task {
            requests_gpu: task_requests_gpu,
        },
    )?;
    Ok(TemplateGrant {
        holder,
        expires: scanned.expires,
        revocation_ids,
    })
}

/// Check an `agent.session` token presented by `holder` for `session_id`:
/// a valid `mesh.peer` chain under `root`, bound to that session, with an
/// expiry that has not passed and is at most [`AGENT_SESSION_MAX_TTL_SECS`]
/// (+ [`MAX_CLOCK_SKEW_SECS`]) after `now`.
pub fn verify_agent_session(
    token: &[u8],
    root: &PublicKey,
    holder: PeerId,
    session_id: &str,
    now: i64,
) -> Result<TemplateGrant, TokenError> {
    let (scanned, revocation_ids) = verify_chain(token, root, holder, now, 0)?;
    if scanned.agent_sessions.is_empty() {
        return Err(TokenError::CapabilityNotGranted(AGENT_SESSION.to_owned()));
    }
    let Some(expires) = scanned.expires else {
        return Err(TokenError::RestrictionNotMet(
            "an agent.session token must carry an expiry".into(),
        ));
    };
    // The template's "short expiry" is enforced here, not only by the
    // builder: a holder can append its own block with any `expires`, so the
    // verifier must not take the presenter's word for it. The clock-skew
    // allowance is the one per-request tokens get.
    let max_secs = AGENT_SESSION_MAX_TTL_SECS + MAX_CLOCK_SKEW_SECS;
    if expires.saturating_sub(now) > max_secs {
        return Err(TokenError::RestrictionNotMet(format!(
            "an {AGENT_SESSION} token must expire within {max_secs}s; this one expires at \
             {expires}, {}s from now",
            expires.saturating_sub(now)
        )));
    }
    check_restrictions(&scanned, Operation::AgentSession(session_id))?;
    Ok(TemplateGrant {
        holder,
        expires: scanned.expires,
        revocation_ids,
    })
}

// ─── Verifying per-request tokens ───────────────────────────────────────────

/// The operation a token is presented for: decides which template
/// restrictions it satisfies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation<'a> {
    /// A one-shot task (`entangle/scheduler/1`). `requests_gpu` is whether
    /// the task asks for a GPU; the wire carries no resource spec today, so
    /// the scheduler always passes `false`.
    Task {
        /// Whether the task requests a GPU.
        requests_gpu: bool,
    },
    /// A streaming task (`entangle/stream/1`).
    Stream,
    /// An operation inside one agent session.
    AgentSession(&'a str),
}

/// Every restriction in the chain must be satisfied; a restriction the
/// operation cannot satisfy (or a verifier cannot check) refuses the token.
fn check_restrictions(scanned: &Scanned, op: Operation<'_>) -> Result<(), TokenError> {
    if scanned.gpu_job && !matches!(op, Operation::Task { requests_gpu: true }) {
        return Err(TokenError::RestrictionNotMet(format!(
            "a {COMPUTE_GPU_JOB} token only authorises tasks that request a GPU"
        )));
    }
    if !scanned.agent_sessions.is_empty() {
        let ok = matches!(op, Operation::AgentSession(id)
            if scanned.agent_sessions.iter().all(|s| s == id));
        if !ok {
            return Err(TokenError::RestrictionNotMet(format!(
                "an {AGENT_SESSION} token only authorises operations in its own session"
            )));
        }
    }
    Ok(())
}

/// What the verifier needs to know about one request.
#[derive(Clone, Copy, Debug)]
pub struct RequestCheck<'a> {
    /// The verifier's own root key (its identity public key).
    pub root: &'a PublicKey,
    /// The transport-authenticated identity of the presenter.
    pub presenter: PeerId,
    /// The digest the token must be bound to.
    pub binding: [u8; 32],
    /// The operation being asked for.
    pub operation: Operation<'a>,
    /// The verifier's clock, Unix seconds.
    pub now_unix_secs: i64,
    /// The length of the frame that carried the token, as the transport
    /// received it — never a length the presenter declares. It earns the
    /// token its late-arrival grace ([`late_arrival_grace_secs`]); 0 for
    /// none.
    pub received_frame_len: usize,
}

/// A per-request token that passed [`verify_request`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRequest {
    /// Its nonce (to record in a [`ReplayCache`]).
    pub nonce: [u8; NONCE_LEN],
    /// Its tightest expiry.
    pub expires: i64,
    /// The late-arrival grace its frame earned
    /// ([`late_arrival_grace_secs`]): it was accepted until
    /// [`VerifiedRequest::accepted_until`].
    pub late_grace_secs: i64,
    /// Its revocation ids (to check against the revocation set).
    pub revocation_ids: Vec<Vec<u8>>,
}

impl VerifiedRequest {
    /// The first moment (Unix seconds) at which this token, in this frame,
    /// counts as expired: its expiry plus its late-arrival grace. A
    /// [`ReplayCache`] must remember the nonce at least this long.
    pub const fn accepted_until(&self) -> i64 {
        self.expires.saturating_add(self.late_grace_secs)
    }
}

/// Verify a per-request token: every stateless check (see the module docs).
/// The revocation set and the replay cache are [`RequestVerifier`]'s.
pub fn verify_request(
    token: &[u8],
    check: &RequestCheck<'_>,
) -> Result<VerifiedRequest, TokenError> {
    let now = check.now_unix_secs;
    let late_grace_secs = late_arrival_grace_secs(check.received_frame_len);
    let (scanned, revocation_ids) =
        verify_chain(token, check.root, check.presenter, now, late_grace_secs)?;

    let max_secs = REQUEST_TOKEN_TTL_SECS + MAX_CLOCK_SKEW_SECS;
    let expires = scanned
        .expires
        .ok_or_else(|| TokenError::ExpiryOutOfWindow {
            max_secs,
            detail: "it carries no expiry".into(),
        })?;
    if expires.saturating_sub(now) > max_secs {
        return Err(TokenError::ExpiryOutOfWindow {
            max_secs,
            detail: format!("it expires at {expires}, {}s from now", expires - now),
        });
    }

    let expected = hex::encode(check.binding);
    if scanned.bindings.is_empty() {
        return Err(TokenError::BindingMismatch(
            "it carries no request binding".into(),
        ));
    }
    if scanned.bindings.iter().any(|b| *b != expected) {
        return Err(TokenError::BindingMismatch(
            "it was attenuated for a different request".into(),
        ));
    }

    let nonce = match scanned.nonces.as_slice() {
        [one] => {
            let mut nonce = [0u8; NONCE_LEN];
            hex::decode_to_slice(one, &mut nonce).map_err(|_| {
                TokenError::BadNonce(format!("`{one}` is not {NONCE_LEN} hex bytes"))
            })?;
            nonce
        }
        [] => return Err(TokenError::BadNonce("it carries none".into())),
        many => return Err(TokenError::BadNonce(format!("it carries {}", many.len()))),
    };

    check_restrictions(&scanned, check.operation)?;
    Ok(VerifiedRequest {
        nonce,
        expires,
        late_grace_secs,
        revocation_ids,
    })
}

// ─── Revocation ─────────────────────────────────────────────────────────────

/// The local set of revoked token ids (spec §6.5: revocation is local).
pub trait RevocationList: std::fmt::Debug + Send + Sync {
    /// `Ok(true)` when any of `ids` is revoked. `Err` when the set cannot be
    /// consulted; the verifier then refuses the token (fail closed).
    fn any_revoked(&self, ids: &[Vec<u8>]) -> Result<bool, String>;
}

/// An in-memory [`RevocationList`], shareable and mutable after the
/// verifier holds it (clones share the set).
#[derive(Clone, Debug, Default)]
pub struct StaticRevocations(Arc<RwLock<HashSet<Vec<u8>>>>);

impl StaticRevocations {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Revoke `ids`.
    pub fn revoke<I: IntoIterator<Item = Vec<u8>>>(&self, ids: I) {
        let mut set = self.0.write().unwrap_or_else(|e| e.into_inner());
        set.extend(ids);
    }
}

impl RevocationList for StaticRevocations {
    fn any_revoked(&self, ids: &[Vec<u8>]) -> Result<bool, String> {
        let set = self.0.read().unwrap_or_else(|e| e.into_inner());
        Ok(ids.iter().any(|id| set.contains(id)))
    }
}

// ─── Replay cache ───────────────────────────────────────────────────────────

/// Nonces of recently accepted per-request tokens (spec §13 #8: "receivers
/// track recent nonces").
///
/// **Policy.** A nonce is remembered until its token stops being accepted
/// — its expiry plus the late-arrival grace of the frame it came in
/// ([`VerifiedRequest::accepted_until`]) — plus [`REPLAY_GRACE_SECS`]
/// (at least [`MAX_CLOCK_SKEW_SECS`]); after that the token itself is
/// refused as expired, so forgetting the nonce cannot let it back in. A
/// replay inside the grace window is therefore still refused as a replay.
/// (A replay must carry the same request binding, so its frame differs from
/// the original only in unbound bytes — the trace context, the policy
/// encoding, the token: far less than 256 KiB, so at most one second more
/// grace, which the retention margin covers.)
///
/// **Bounds.** At most `capacity` nonces are tracked, and at most
/// `per_peer` for one presenter. When either bound is reached (after
/// dropping entries past their retention) a new token is **refused** with
/// [`TokenError::ReplayCacheFull`] — never accepted unchecked — so a flood
/// costs availability, not replay protection; the per-peer bound keeps one
/// presenter from filling the cache for the others. A nonce is held at most
/// [`REQUEST_TOKEN_TTL_SECS`] + [`MAX_CLOCK_SKEW_SECS`] + grace +
/// [`REPLAY_GRACE_SECS`]: 120 s for a frame under 256 KiB, 184 s for the
/// largest task frame (16 MiB, 64 s of grace), never more than 720 s
/// ([`MAX_LATE_ARRIVAL_GRACE_SECS`]). Each second of grace costs the
/// presenter 256 KiB of received bytes, so holding the default per-peer
/// share (16 384 nonces) with maximum-size frames takes about 1.4 GiB/s of
/// sustained traffic; the defaults keep their headroom.
#[derive(Debug)]
pub struct ReplayCache {
    entries: HashMap<[u8; NONCE_LEN], (i64, PeerId)>,
    by_expiry: BTreeSet<(i64, [u8; NONCE_LEN])>,
    per_peer: HashMap<PeerId, usize>,
    capacity: usize,
    per_peer_capacity: usize,
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new(DEFAULT_REPLAY_CAPACITY, DEFAULT_REPLAY_PER_PEER)
    }
}

impl ReplayCache {
    /// A cache holding at most `capacity` nonces, at most `per_peer` of them
    /// for one presenter (each at least 1).
    pub fn new(capacity: usize, per_peer: usize) -> Self {
        Self {
            entries: HashMap::new(),
            by_expiry: BTreeSet::new(),
            per_peer: HashMap::new(),
            capacity: capacity.max(1),
            per_peer_capacity: per_peer.max(1),
        }
    }

    /// Nonces tracked right now (including ones not yet pruned).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is tracked.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Record `nonce`, presented by `presenter` in a token accepted until
    /// `accepted_until` (its expiry plus its frame's late-arrival grace:
    /// [`VerifiedRequest::accepted_until`]), or refuse it:
    /// [`TokenError::Replayed`] if it is already tracked,
    /// [`TokenError::ReplayCacheFull`] if a bound is reached. The nonce is
    /// remembered until `accepted_until` + [`REPLAY_GRACE_SECS`].
    pub fn check_and_record(
        &mut self,
        nonce: [u8; NONCE_LEN],
        presenter: PeerId,
        accepted_until: i64,
        now: i64,
    ) -> Result<(), TokenError> {
        self.prune(now);
        if self.entries.contains_key(&nonce) {
            return Err(TokenError::Replayed);
        }
        if self.entries.len() >= self.capacity {
            return Err(TokenError::ReplayCacheFull(format!(
                "{} live nonces, the cap",
                self.entries.len()
            )));
        }
        let held = self.per_peer.get(&presenter).copied().unwrap_or(0);
        if held >= self.per_peer_capacity {
            return Err(TokenError::ReplayCacheFull(format!(
                "this peer holds {held} live nonces, the per-peer cap"
            )));
        }
        self.entries.insert(nonce, (accepted_until, presenter));
        self.by_expiry.insert((accepted_until, nonce));
        *self.per_peer.entry(presenter).or_insert(0) += 1;
        Ok(())
    }

    /// Forget every nonce whose token stopped being accepted more than
    /// [`REPLAY_GRACE_SECS`] before `now`.
    fn prune(&mut self, now: i64) {
        while let Some(&(accepted_until, nonce)) = self.by_expiry.first() {
            if accepted_until.saturating_add(REPLAY_GRACE_SECS) > now {
                break;
            }
            self.by_expiry.pop_first();
            if let Some((_, peer)) = self.entries.remove(&nonce) {
                if let Some(n) = self.per_peer.get_mut(&peer) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        self.per_peer.remove(&peer);
                    }
                }
            }
        }
    }
}

// ─── The verifier with state ────────────────────────────────────────────────

/// A node's verifier for per-request tokens: [`verify_request`] under the
/// node's own key, then the revocation set, then the replay cache (so a
/// refused token never takes a cache slot).
#[derive(Debug)]
pub struct RequestVerifier {
    root: PublicKey,
    local_public_key: [u8; 32],
    replay: Mutex<ReplayCache>,
    revocations: Option<Arc<dyn RevocationList>>,
}

impl RequestVerifier {
    /// Verify tokens rooted at `local_public_key` (this node's identity
    /// key), with a default [`ReplayCache`] and no revocation set.
    pub fn new(local_public_key: &[u8; 32]) -> Result<Self, TokenError> {
        Ok(Self {
            root: root_public_key(local_public_key)?,
            local_public_key: *local_public_key,
            replay: Mutex::new(ReplayCache::default()),
            revocations: None,
        })
    }

    /// Consult `revocations` for every token.
    #[must_use]
    pub fn with_revocations(mut self, revocations: Arc<dyn RevocationList>) -> Self {
        self.revocations = Some(revocations);
        self
    }

    /// Use `cache` as the replay cache (e.g. smaller bounds).
    #[must_use]
    pub fn with_replay_cache(mut self, cache: ReplayCache) -> Self {
        self.replay = Mutex::new(cache);
        self
    }

    /// The identity public key tokens must be rooted at.
    pub const fn local_public_key(&self) -> &[u8; 32] {
        &self.local_public_key
    }

    /// The node's peer id (derived from [`Self::local_public_key`]).
    pub fn local_peer_id(&self) -> PeerId {
        PeerId::from_public_key_bytes(&self.local_public_key)
    }

    /// Verify `token`, presented by the transport-authenticated `presenter`
    /// for `operation` on a request whose digest is `binding`, at the
    /// current wall-clock time, with no late-arrival grace (as for a frame
    /// under 256 KiB; see [`Self::verify_received`]).
    pub fn verify(
        &self,
        token: &[u8],
        presenter: PeerId,
        binding: [u8; 32],
        operation: Operation<'_>,
    ) -> Result<VerifiedRequest, TokenError> {
        self.verify_received_at(token, presenter, binding, operation, 0, unix_now())
    }

    /// [`Self::verify`] at an explicit `now` (Unix seconds).
    pub fn verify_at(
        &self,
        token: &[u8],
        presenter: PeerId,
        binding: [u8; 32],
        operation: Operation<'_>,
        now: i64,
    ) -> Result<VerifiedRequest, TokenError> {
        self.verify_received_at(token, presenter, binding, operation, 0, now)
    }

    /// [`Self::verify`] for a token that arrived in a frame of
    /// `received_frame_len` bytes — the length the transport received, not
    /// one the presenter declares — which earns it the late-arrival grace
    /// of [`late_arrival_grace_secs`].
    pub fn verify_received(
        &self,
        token: &[u8],
        presenter: PeerId,
        binding: [u8; 32],
        operation: Operation<'_>,
        received_frame_len: usize,
    ) -> Result<VerifiedRequest, TokenError> {
        self.verify_received_at(
            token,
            presenter,
            binding,
            operation,
            received_frame_len,
            unix_now(),
        )
    }

    /// [`Self::verify_received`] at an explicit `now` (Unix seconds).
    pub fn verify_received_at(
        &self,
        token: &[u8],
        presenter: PeerId,
        binding: [u8; 32],
        operation: Operation<'_>,
        received_frame_len: usize,
        now: i64,
    ) -> Result<VerifiedRequest, TokenError> {
        let verified = verify_request(
            token,
            &RequestCheck {
                root: &self.root,
                presenter,
                binding,
                operation,
                now_unix_secs: now,
                received_frame_len,
            },
        )?;
        if let Some(revocations) = &self.revocations {
            match revocations.any_revoked(&verified.revocation_ids) {
                Ok(false) => {}
                Ok(true) => return Err(TokenError::Revoked),
                Err(e) => return Err(TokenError::RevocationsUnavailable(e)),
            }
        }
        self.replay
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .check_and_record(verified.nonce, presenter, verified.accepted_until(), now)?;
        Ok(verified)
    }
}

/// The current wall-clock time in Unix seconds (the clock [`RequestVerifier::verify`]
/// and presenters use).
pub fn now_unix_secs() -> i64 {
    unix_now()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_fact_accepts_only_single_term_facts() {
        assert_eq!(split_fact("peer(\"ab\");"), Some(("peer", "\"ab\"")));
        assert_eq!(split_fact("expires(12);"), Some(("expires", "12")));
        assert_eq!(split_fact("expires(12)"), None, "no semicolon");
        assert_eq!(split_fact("check if time($t), $t < 3;"), None);
        assert_eq!(split_fact("a($x) <- b($x);"), None);
        assert_eq!(split_fact("pair(1, 2);"), None);
        assert_eq!(split_fact("Peer(\"x\");"), None);
        assert_eq!(split_fact("peer();"), None);
    }

    #[test]
    fn string_terms_refuse_escapes() {
        assert_eq!(string_term("\"mesh.peer\""), Some("mesh.peer"));
        assert_eq!(string_term("\"a\\\"b\""), None);
        assert_eq!(string_term("12"), None);
    }

    #[test]
    fn labels_cover_every_variant_once() {
        let all = [
            TokenError::Build(String::new()),
            TokenError::Expired { expires: 0, now: 0 },
            TokenError::Missing,
            TokenError::Malformed(String::new()),
            TokenError::BadSignature(String::new()),
            TokenError::WrongHolder {
                issued_to: String::new(),
                presenter: String::new(),
            },
            TokenError::CapabilityNotGranted(String::new()),
            TokenError::ExpiryOutOfWindow {
                max_secs: 0,
                detail: String::new(),
            },
            TokenError::BindingMismatch(String::new()),
            TokenError::BadNonce(String::new()),
            TokenError::Replayed,
            TokenError::ReplayCacheFull(String::new()),
            TokenError::Revoked,
            TokenError::UnexpectedContent(String::new()),
            TokenError::RestrictionNotMet(String::new()),
            TokenError::RevocationsUnavailable(String::new()),
        ];
        let labels: Vec<&str> = all.iter().map(TokenError::label).collect();
        assert_eq!(labels, TokenError::LABELS);
    }
}
