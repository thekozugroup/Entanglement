//! Capability tokens on the remote paths (spec §6.1.1, §6.3 step 4, §7.4,
//! §13 #8): every `entangle/scheduler/1` task frame and every
//! `entangle/stream/1` `Open` carries a per-request attenuation of the
//! `mesh.peer` token the worker issued to the submitter while pairing.
//!
//! # Submitter side
//!
//! A [`CapabilityTokens`] source says which token to present to a peer
//! (the daemon's comes from `peers.toml`; tests use [`StaticTokens`]). For
//! each request the submitter attenuates it
//! ([`entangle_biscuits::templates::present_for_request`]) with a 60 s
//! expiry, a fresh nonce and a binding to the request:
//!
//! * a task: [`task_binding`] — `BLAKE3("entangle/capability/task/v1" ‖ 0x00
//!   ‖ task_id ‖ u32 BE len(plugin) ‖ plugin ‖ BLAKE3(input) ‖ policy_hash)`;
//! * a stream: [`stream_binding`] — `BLAKE3("entangle/capability/stream/v1"
//!   ‖ 0x00 ‖ task_id ‖ policy_hash ‖ request)`, where `request` is the
//!   stream's [`request_digest`](crate::stream::request_digest) (plugin,
//!   input digest, every requested limit).
//!
//! These are the fields that identify what is being asked and that the
//! worker sees unchanged; the per-attempt `traceparent` is not bound (it
//! grants nothing), nor is the token itself.
//!
//! **When.** The attenuation is made per attempt, once the attempt's link
//! has connected and immediately before the frame is written: a task
//! frame's token is appended by the frame the router builds for that
//! attempt ([`TransportRouter::request_tracked`]), a stream `Open`'s when
//! the stream's link has opened it. Time spent dialling — including the
//! router falling back from one transport to the next — never counts
//! against the token's 60 s, and every attempt (a resend too) carries a
//! fresh nonce. An attempt whose frame was sent is never retried elsewhere.
//!
//! # Worker side
//!
//! [`CapabilityGate`] runs after the peer allowlist and the frame decode,
//! before any other work: [`RequestVerifier`] (root = this node's identity
//! key, holder = the transport-authenticated peer, `mesh.peer`, expiry
//! window, binding, nonce, revocation set, replay cache). The gate sees a
//! token only once the whole frame is in, so a large frame earns a
//! late-arrival grace measured on the bytes the transport received: one
//! second per 256 KiB, at most 600 s
//! ([`templates::late_arrival_grace_secs`]); its token is expired only once
//! `now >= expires + grace`, and its nonce is remembered that much longer,
//! so a replay inside the grace is still refused. A frame without a
//! token is refused ([`RemoteErrorCode::CapabilityRequired`],
//! `ENTANGLE-E0450`) unless `[trust] require_capability_tokens = false`, in
//! which case it is accepted and counted (`tokenless_accepted`); a frame
//! *with* a token is always fully verified. Refusals are
//! [`RemoteErrorCode::CapabilityRejected`] with the `ENTANGLE-E04xx` text,
//! counted in `entangle_remote_capability_checks_total{path, outcome}` and
//! `entangle_biscuit_verification_seconds{outcome}`.
//!
//! [`TransportRouter::request_tracked`]: crate::transport::TransportRouter::request_tracked
//! [`RemoteErrorCode::CapabilityRequired`]: crate::wire::RemoteErrorCode::CapabilityRequired
//! [`RemoteErrorCode::CapabilityRejected`]: crate::wire::RemoteErrorCode::CapabilityRejected

use std::collections::HashMap;
use std::sync::Arc;

use entangle_biscuits::templates::{
    self, Operation, RequestVerifier, RevocationList, TokenError, VerifiedRequest,
};
use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;
use parking_lot::RwLock;

use crate::wire::RemoteTaskRequest;
use crate::work_unit::PolicyHash;

pub use entangle_biscuits::templates::{MAX_TOKEN_BYTES, REQUEST_TOKEN_TTL_SECS};

/// Domain separator of [`task_binding`].
pub const TASK_BINDING_DOMAIN: &[u8] = b"entangle/capability/task/v1";
/// Domain separator of [`stream_binding`].
pub const STREAM_BINDING_DOMAIN: &[u8] = b"entangle/capability/stream/v1";

// ─── Submitter side ─────────────────────────────────────────────────────────

/// A long-lived token this node holds for one peer, and the key it is
/// rooted at (the peer's identity key: the peer minted it).
#[derive(Clone, PartialEq, Eq)]
pub struct HeldToken {
    /// The serialized `mesh.peer` biscuit.
    pub token: Vec<u8>,
    /// The issuing peer's Ed25519 public key.
    pub issuer_public_key: [u8; 32],
}

impl std::fmt::Debug for HeldToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The token is a bearer credential for its holder: never log it.
        f.debug_struct("HeldToken")
            .field(
                "issuer",
                &PeerId::from_public_key_bytes(&self.issuer_public_key),
            )
            .field("bytes", &self.token.len())
            .finish()
    }
}

impl HeldToken {
    /// What `issuer` would hand `holder` while pairing: a `mesh.peer` token
    /// rooted at `issuer`'s identity key. The shared helper for tests that
    /// wire nodes together by hand instead of pairing them.
    pub fn minted(issuer: &IdentityKeyPair, holder: PeerId) -> Result<Self, TokenError> {
        Ok(Self {
            token: templates::mint_mesh_peer(issuer, holder, None)?.bytes,
            issuer_public_key: *issuer.public().as_bytes(),
        })
    }

    /// Attenuate for one request bound to `binding`, expiring
    /// [`REQUEST_TOKEN_TTL_SECS`] from now.
    pub fn present(&self, binding: [u8; 32]) -> Result<Vec<u8>, TokenError> {
        templates::present_for_request(&self.token, &self.issuer_public_key, binding, token_clock())
    }
}

/// The clock tokens are presented and verified against: the wall clock
/// (Unix seconds), which this crate's unit tests can move (`test_clock`).
fn token_clock() -> i64 {
    let now = templates::now_unix_secs();
    #[cfg(test)]
    let now = now.saturating_add(test_clock::offset());
    now
}

/// A time source for this crate's unit tests only: moves the clock that
/// [`HeldToken::present`] and [`CapabilityGate::check`] read, so a test can
/// let a token's lifetime pass without waiting for it.
///
/// The offset is per thread: a test that moves it runs on a current-thread
/// runtime (`#[tokio::test]`'s default), where every task it spawns — the
/// dispatch, the links, the server — runs on the test's own thread, and
/// tests running in parallel never see each other's clock.
#[cfg(test)]
pub(crate) mod test_clock {
    use std::cell::Cell;

    thread_local! {
        static OFFSET: Cell<i64> = const { Cell::new(0) };
    }

    /// Move this thread's token clock forward by `secs`.
    pub(crate) fn advance(secs: i64) {
        OFFSET.with(|o| o.set(o.get().saturating_add(secs)));
    }

    /// How far this thread's token clock is ahead of the wall clock.
    pub(crate) fn offset() -> i64 {
        OFFSET.with(Cell::get)
    }
}

/// Where a submitter finds the token to present to a peer.
pub trait CapabilityTokens: std::fmt::Debug + Send + Sync {
    /// The token issued to this node by `peer`, if any. `None` sends the
    /// request without one (refused by a peer that requires tokens).
    fn token_for(&self, peer: &PeerId) -> Option<HeldToken>;
}

/// An in-memory [`CapabilityTokens`] (tests, embedders). Clones share the
/// map.
#[derive(Clone, Debug, Default)]
pub struct StaticTokens(Arc<RwLock<HashMap<PeerId, HeldToken>>>);

impl StaticTokens {
    /// No tokens.
    pub fn new() -> Self {
        Self::default()
    }

    /// Hold `token` for `peer` (replacing any earlier one).
    pub fn insert(&self, peer: PeerId, token: HeldToken) {
        self.0.write().insert(peer, token);
    }

    /// Forget the token for `peer`.
    pub fn remove(&self, peer: &PeerId) -> Option<HeldToken> {
        self.0.write().remove(peer)
    }

    /// Hold, for the peer whose identity is `issuer`, the token it would
    /// issue to `holder` while pairing (see [`HeldToken::minted`]).
    pub fn paired_with(&self, issuer: &IdentityKeyPair, holder: PeerId) -> Result<(), TokenError> {
        let peer = PeerId::from_public_key_bytes(issuer.public().as_bytes());
        self.insert(peer, HeldToken::minted(issuer, holder)?);
        Ok(())
    }
}

impl CapabilityTokens for StaticTokens {
    fn token_for(&self, peer: &PeerId) -> Option<HeldToken> {
        self.0.read().get(peer).cloned()
    }
}

/// The per-request token for `peer` from `tokens`, bound to `binding`; `None`
/// when there is no token source, no token for `peer`, or the stored token
/// cannot be attenuated (logged: the request then goes without one, and a
/// peer that requires tokens refuses it with an error naming the fix).
///
/// Its 60 s run from this call: call it for the attempt that sends the
/// request, once that attempt's connection is set up.
pub fn present_to(
    tokens: Option<&Arc<dyn CapabilityTokens>>,
    peer: &PeerId,
    binding: [u8; 32],
) -> Option<Vec<u8>> {
    let held = tokens?.token_for(peer)?;
    if PeerId::from_public_key_bytes(&held.issuer_public_key) != *peer {
        tracing::warn!(%peer, "capability token for this peer is rooted at another key; sending none");
        return None;
    }
    match held.present(binding) {
        Ok(token) => Some(token),
        Err(e) => {
            tracing::warn!(%peer, error = %e, "stored capability token is unusable; sending none (re-pair with `entangle pair`)");
            None
        }
    }
}

/// The request binding of a task frame (see the module docs).
pub fn task_binding(request: &RemoteTaskRequest) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(TASK_BINDING_DOMAIN);
    h.update(&[0]);
    h.update(&request.task_id);
    // A plugin id is far below 4 GiB; saturate rather than wrap regardless.
    let plugin_len = u32::try_from(request.plugin.len()).unwrap_or(u32::MAX);
    h.update(&plugin_len.to_be_bytes());
    h.update(request.plugin.as_bytes());
    h.update(blake3::hash(&request.input).as_bytes());
    h.update(&request.policy_hash.0);
    *h.finalize().as_bytes()
}

/// The request binding of a stream `Open` (see the module docs): its task
/// id, sealed policy hash and [`request_digest`](crate::stream::request_digest).
pub fn stream_binding(
    task_id: &[u8; 16],
    policy_hash: &PolicyHash,
    request: &[u8; 32],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(STREAM_BINDING_DOMAIN);
    h.update(&[0]);
    h.update(task_id);
    h.update(&policy_hash.0);
    h.update(request);
    *h.finalize().as_bytes()
}

// ─── Worker side ────────────────────────────────────────────────────────────

/// Which remote path a token was presented on (the metric `path` label).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatePath {
    /// `entangle/scheduler/1` task frames.
    Task,
    /// `entangle/stream/1` `Open` frames.
    Stream,
}

impl GatePath {
    /// The metric label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Task => "task",
            Self::Stream => "stream",
        }
    }

    fn operation(self) -> Operation<'static> {
        match self {
            // The task frame carries no resource spec: a task never counts
            // as requesting a GPU, so a `compute.gpu-job` token is refused.
            Self::Task => Operation::Task {
                requests_gpu: false,
            },
            Self::Stream => Operation::Stream,
        }
    }
}

/// What the gate decided for a request it admits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admission {
    /// The token verified.
    Verified(VerifiedRequest),
    /// No token, admitted because tokens are not required.
    Tokenless,
}

/// A refusal: `missing` when no token was presented (the gate is on),
/// otherwise the verification failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// Why, with its `ENTANGLE-E04xx` code.
    pub error: TokenError,
}

impl Refusal {
    /// Whether the request simply carried no token.
    pub fn is_missing(&self) -> bool {
        self.error == TokenError::Missing
    }
}

/// The worker's capability check for remote tasks and streams. Shared (in an
/// `Arc`) by the task and stream servers so they share one replay cache and
/// revocation set.
#[derive(Debug)]
pub struct CapabilityGate {
    verifier: RequestVerifier,
    require: bool,
    metrics: Option<entangle_observability::Registry>,
}

impl CapabilityGate {
    /// A gate for the node whose identity public key is `local_public_key`,
    /// requiring a token on every request (the default; fail closed).
    pub fn new(local_public_key: &[u8; 32]) -> Result<Self, TokenError> {
        Ok(Self {
            verifier: RequestVerifier::new(local_public_key)?,
            require: true,
            metrics: None,
        })
    }

    /// A gate for `identity`'s node.
    pub fn for_identity(identity: &IdentityKeyPair) -> Result<Self, TokenError> {
        Self::new(identity.public().as_bytes())
    }

    /// Whether a request without a token is refused (`true`, the default)
    /// or admitted (`false`: migration only — see
    /// `[trust] require_capability_tokens`).
    #[must_use]
    pub fn require_tokens(mut self, require: bool) -> Self {
        self.require = require;
        self
    }

    /// Consult `revocations` for every token.
    #[must_use]
    pub fn with_revocations(mut self, revocations: Arc<dyn RevocationList>) -> Self {
        self.verifier = self.verifier.with_revocations(revocations);
        self
    }

    /// Use `cache` as the replay cache.
    #[must_use]
    pub fn with_replay_cache(mut self, cache: templates::ReplayCache) -> Self {
        self.verifier = self.verifier.with_replay_cache(cache);
        self
    }

    /// Count checks into `registry`.
    #[must_use]
    pub fn with_metrics(mut self, registry: entangle_observability::Registry) -> Self {
        self.metrics = Some(registry);
        self
    }

    /// Whether tokenless requests are refused.
    pub const fn requires_tokens(&self) -> bool {
        self.require
    }

    /// The identity key tokens must be rooted at.
    pub const fn local_public_key(&self) -> &[u8; 32] {
        self.verifier.local_public_key()
    }

    /// This node's peer id.
    pub fn local_peer_id(&self) -> PeerId {
        self.verifier.local_peer_id()
    }

    /// Check the `token` (if any) that `presenter` — the
    /// transport-authenticated peer — sent with a request on `path` whose
    /// binding is `binding`, in a frame of `received_frame_len` bytes: the
    /// length the transport received, which earns the token its
    /// late-arrival grace ([`templates::late_arrival_grace_secs`]). Never a
    /// length the request itself declares.
    pub fn check(
        &self,
        presenter: PeerId,
        token: Option<&[u8]>,
        binding: [u8; 32],
        path: GatePath,
        received_frame_len: usize,
    ) -> Result<Admission, Refusal> {
        let Some(token) = token else {
            if self.require {
                self.count(path, TokenError::Missing.label());
                return Err(Refusal {
                    error: TokenError::Missing,
                });
            }
            self.count(path, "tokenless_accepted");
            tracing::debug!(%presenter, path = path.as_str(), "admitted a request without a capability token ([trust] require_capability_tokens = false)");
            return Ok(Admission::Tokenless);
        };
        let started = std::time::Instant::now();
        let result = self.verifier.verify_received_at(
            token,
            presenter,
            binding,
            path.operation(),
            received_frame_len,
            token_clock(),
        );
        if let Some(reg) = &self.metrics {
            entangle_observability::catalog::biscuit_verification(
                reg,
                result.is_ok(),
                started.elapsed().as_secs_f64(),
            );
        }
        match result {
            Ok(v) => {
                self.count(path, "ok");
                Ok(Admission::Verified(v))
            }
            Err(error) => {
                self.count(path, error.label());
                tracing::warn!(
                    %presenter,
                    path = path.as_str(),
                    %error,
                    frame_bytes = received_frame_len,
                    late_grace_secs = templates::late_arrival_grace_secs(received_frame_len),
                    "refused a remote request: capability token rejected"
                );
                Err(Refusal { error })
            }
        }
    }

    fn count(&self, path: GatePath, outcome: &str) {
        if let Some(reg) = &self.metrics {
            entangle_observability::catalog::remote_capability(reg, path.as_str(), outcome);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use entangle_observability::catalog::REMOTE_CAPABILITY_OUTCOMES;

    #[test]
    fn every_refusal_label_is_a_bounded_metric_outcome() {
        for label in TokenError::LABELS {
            assert!(REMOTE_CAPABILITY_OUTCOMES.contains(&label), "{label}");
        }
        assert!(REMOTE_CAPABILITY_OUTCOMES.contains(&"ok"));
        assert!(REMOTE_CAPABILITY_OUTCOMES.contains(&"tokenless_accepted"));
    }

    fn request(task_id: u8, plugin: &str, input: &[u8], policy: u8) -> RemoteTaskRequest {
        RemoteTaskRequest {
            task_id: [task_id; 16],
            plugin: plugin.into(),
            input: input.to_vec(),
            timeout_ms: 1,
            max_input_bytes: 1,
            max_output_bytes: 1,
            policy: vec![],
            policy_hash: PolicyHash([policy; 32]),
            traceparent: None,
            capability: None,
        }
    }

    #[test]
    fn the_task_binding_covers_what_identifies_the_request() {
        let base = request(1, "p/x@1.0.0", b"in", 1);
        let b = task_binding(&base);
        assert_ne!(
            b,
            task_binding(&request(2, "p/x@1.0.0", b"in", 1)),
            "task id"
        );
        assert_ne!(
            b,
            task_binding(&request(1, "p/y@1.0.0", b"in", 1)),
            "plugin"
        );
        assert_ne!(
            b,
            task_binding(&request(1, "p/x@1.0.0", b"other", 1)),
            "input"
        );
        assert_ne!(
            b,
            task_binding(&request(1, "p/x@1.0.0", b"in", 2)),
            "policy"
        );
        // Not bound: the clamped limits, the trace context, the token.
        let mut same = base.clone();
        same.timeout_ms = 99;
        same.traceparent = Some("00-x".into());
        same.capability = Some(vec![1]);
        assert_eq!(b, task_binding(&same));
        assert_ne!(
            stream_binding(&[1; 16], &PolicyHash([1; 32]), &[0; 32]),
            stream_binding(&[1; 16], &PolicyHash([1; 32]), &[1; 32])
        );
    }

    #[test]
    fn the_gate_admits_tokenless_requests_only_when_told_to_and_counts_them() {
        let worker = IdentityKeyPair::generate();
        let peer = PeerId::from_public_key_bytes(&[3; 32]);
        let reg = entangle_observability::Registry::new();
        let on = CapabilityGate::for_identity(&worker)
            .unwrap()
            .with_metrics(reg.clone());
        let refusal = on
            .check(peer, None, [0; 32], GatePath::Task, 0)
            .unwrap_err();
        assert!(refusal.is_missing());
        let off = CapabilityGate::for_identity(&worker)
            .unwrap()
            .require_tokens(false)
            .with_metrics(reg.clone());
        assert_eq!(
            off.check(peer, None, [0; 32], GatePath::Stream, 0),
            Ok(Admission::Tokenless)
        );
        // A token, when present, is verified even with the gate off.
        assert!(off
            .check(peer, Some(&[1, 2, 3]), [0; 32], GatePath::Task, 3)
            .is_err());
        let text = reg.render();
        assert!(text.contains("outcome=\"tokenless_accepted\""), "{text}");
        assert!(text.contains("outcome=\"missing\""), "{text}");
        assert!(text.contains("outcome=\"malformed\""), "{text}");
    }

    #[test]
    fn a_presented_token_passes_the_gate_once() {
        let worker = IdentityKeyPair::generate();
        let me = IdentityKeyPair::generate();
        let me_id = PeerId::from_public_key_bytes(me.public().as_bytes());
        let worker_id = PeerId::from_public_key_bytes(worker.public().as_bytes());
        let tokens = StaticTokens::new();
        tokens.paired_with(&worker, me_id).unwrap();
        let source: Arc<dyn CapabilityTokens> = Arc::new(tokens);
        let token = present_to(Some(&source), &worker_id, [5; 32]).unwrap();
        assert!(
            present_to(Some(&source), &me_id, [5; 32]).is_none(),
            "no token for us"
        );
        let gate = CapabilityGate::for_identity(&worker).unwrap();
        assert!(matches!(
            gate.check(me_id, Some(&token), [5; 32], GatePath::Task, token.len()),
            Ok(Admission::Verified(_))
        ));
        assert_eq!(
            gate.check(me_id, Some(&token), [5; 32], GatePath::Task, token.len())
                .unwrap_err()
                .error,
            TokenError::Replayed
        );
    }
}
