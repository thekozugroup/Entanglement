//! The curated templates (spec §6.6) and the per-request token protocol,
//! against real tokens minted with real identity keys.

use std::sync::Arc;

use biscuit_auth::builder::BlockBuilder;
use biscuit_auth::Biscuit;
use entangle_biscuits::templates::{
    attenuate_agent_session, attenuate_for_request, attenuate_gpu_job, mint_mesh_peer,
    present_for_request, root_keypair, root_public_key, verify_agent_session, verify_gpu_job,
    verify_mesh_peer_grant, verify_request, Operation, ReplayCache, RequestCheck,
    RequestRestrictions, RequestVerifier, RevocationList, StaticRevocations, TokenError,
    MAX_CLOCK_SKEW_SECS, REQUEST_TOKEN_TTL_SECS,
};
use entangle_biscuits::BiscuitError;
use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;

const NOW: i64 = 1_735_689_600;
const BINDING: [u8; 32] = [7; 32];

struct Node {
    key: IdentityKeyPair,
}

impl Node {
    fn new() -> Self {
        Self {
            key: IdentityKeyPair::generate(),
        }
    }
    fn id(&self) -> PeerId {
        PeerId::from_public_key_bytes(self.key.public().as_bytes())
    }
    fn public(&self) -> [u8; 32] {
        *self.key.public().as_bytes()
    }
}

/// Worker `w` issued a mesh.peer token to `holder`.
fn grant(w: &Node, holder: &Node) -> Vec<u8> {
    mint_mesh_peer(&w.key, holder.id(), None).unwrap().bytes
}

fn request(token: &[u8], issuer: &Node, expires: i64, nonce: u8, binding: [u8; 32]) -> Vec<u8> {
    attenuate_for_request(
        token,
        &issuer.public(),
        &RequestRestrictions {
            expires,
            nonce: [nonce; 16],
            binding,
        },
    )
    .unwrap()
}

fn check<'a>(
    root: &'a biscuit_auth::PublicKey,
    presenter: PeerId,
    op: Operation<'a>,
) -> RequestCheck<'a> {
    RequestCheck {
        root,
        presenter,
        binding: BINDING,
        operation: op,
        now_unix_secs: NOW,
    }
}

const TASK: Operation<'static> = Operation::Task {
    requests_gpu: false,
};

/// Append a raw block (any Datalog) under the issuer's key.
fn append_raw(token: &[u8], issuer: &Node, facts: &[&str], checks: &[&str]) -> Vec<u8> {
    let b = Biscuit::from(token, root_public_key(&issuer.public()).unwrap()).unwrap();
    let mut block = BlockBuilder::new();
    for f in facts {
        block = block.fact(*f).unwrap();
    }
    for c in checks {
        block = block.check(*c).unwrap();
    }
    b.append(block).unwrap().to_vec().unwrap()
}

#[test]
fn a_token_minted_with_an_identity_verifies_under_its_public_key() {
    let (w, b) = (Node::new(), Node::new());
    let minted = mint_mesh_peer(&w.key, b.id(), None).unwrap();
    assert_eq!(minted.revocation_ids.len(), 1);
    let g = verify_mesh_peer_grant(&minted.bytes, &w.public(), b.id(), NOW).unwrap();
    assert_eq!(g.holder, b.id());
    assert_eq!(g.expires, None, "a pairing token is long-lived");
    assert_eq!(g.revocation_ids, minted.revocation_ids);
    // The root key pair is the identity key itself.
    assert_eq!(
        root_keypair(&w.key).unwrap().public(),
        root_public_key(&w.public()).unwrap()
    );
}

#[test]
fn a_grant_is_checked_for_holder_issuer_and_shape() {
    let (w, b, c) = (Node::new(), Node::new(), Node::new());
    let token = grant(&w, &b);
    assert!(matches!(
        verify_mesh_peer_grant(&token, &w.public(), c.id(), NOW),
        Err(TokenError::WrongHolder { .. })
    ));
    assert!(matches!(
        verify_mesh_peer_grant(&token, &c.public(), b.id(), NOW),
        Err(TokenError::BadSignature(_))
    ));
    let attenuated = request(&token, &w, NOW + 30, 1, BINDING);
    assert!(matches!(
        verify_mesh_peer_grant(&attenuated, &w.public(), b.id(), NOW),
        Err(TokenError::UnexpectedContent(_))
    ));
    let expiring = mint_mesh_peer(&w.key, b.id(), Some(NOW)).unwrap().bytes;
    assert!(matches!(
        verify_mesh_peer_grant(&expiring, &w.public(), b.id(), NOW),
        Err(TokenError::Expired { .. })
    ));
}

#[test]
fn a_presented_token_verifies() {
    let (w, b) = (Node::new(), Node::new());
    let root = root_public_key(&w.public()).unwrap();
    let presented = present_for_request(&grant(&w, &b), &w.public(), BINDING, NOW).unwrap();
    let v = verify_request(&presented, &check(&root, b.id(), TASK)).unwrap();
    assert_eq!(v.expires, NOW + REQUEST_TOKEN_TTL_SECS);
    assert_eq!(v.revocation_ids.len(), 2);
    // Streams take the same token shape.
    verify_request(&presented, &check(&root, b.id(), Operation::Stream)).unwrap();
}

#[test]
fn a_token_minted_by_another_node_is_refused() {
    let (w, other, b) = (Node::new(), Node::new(), Node::new());
    let root = root_public_key(&w.public()).unwrap();
    let presented = request(&grant(&other, &b), &other, NOW + 30, 1, BINDING);
    let err = verify_request(&presented, &check(&root, b.id(), TASK)).unwrap_err();
    assert!(matches!(err, TokenError::BadSignature(_)), "{err}");
    assert!(err.to_string().starts_with("ENTANGLE-E0452"));
}

#[test]
fn a_token_issued_to_another_peer_is_refused() {
    let (w, b, c) = (Node::new(), Node::new(), Node::new());
    let root = root_public_key(&w.public()).unwrap();
    let stolen = request(&grant(&w, &b), &w, NOW + 30, 1, BINDING);
    let err = verify_request(&stolen, &check(&root, c.id(), TASK)).unwrap_err();
    assert!(matches!(err, TokenError::WrongHolder { .. }), "{err}");
    assert!(err.to_string().starts_with("ENTANGLE-E0453"));
}

#[test]
fn malformed_and_oversized_bytes_are_refused() {
    let w = Node::new();
    let root = root_public_key(&w.public()).unwrap();
    let b = Node::new();
    for junk in [vec![], vec![1, 2, 3], vec![0u8; 5_000]] {
        let err = verify_request(&junk, &check(&root, b.id(), TASK)).unwrap_err();
        assert!(matches!(err, TokenError::Malformed(_)), "{err}");
    }
}

#[test]
fn a_token_without_the_capability_is_refused() {
    let (w, b) = (Node::new(), Node::new());
    let root = root_public_key(&w.public()).unwrap();
    let claims = entangle_biscuits::ClaimSet::new()
        .issued_to(b.id())
        .capability("compute.cpu");
    let other_cap = entangle_biscuits::mint(&root_keypair(&w.key).unwrap(), &claims).unwrap();
    let presented = request(&other_cap, &w, NOW + 30, 1, BINDING);
    assert!(matches!(
        verify_request(&presented, &check(&root, b.id(), TASK)),
        Err(TokenError::CapabilityNotGranted(_))
    ));
}

#[test]
fn an_expired_token_is_refused_with_the_shared_e0412_message() {
    let (w, b) = (Node::new(), Node::new());
    let root = root_public_key(&w.public()).unwrap();
    let presented = request(&grant(&w, &b), &w, NOW - 1, 1, BINDING);
    let err = verify_request(&presented, &check(&root, b.id(), TASK)).unwrap_err();
    assert_eq!(
        err,
        TokenError::Expired {
            expires: NOW - 1,
            now: NOW
        }
    );
    // Exactly the shared verifier's wording for an expired token.
    let shared = BiscuitError::Verify(format!("token expired at {} (now={NOW})", NOW - 1));
    assert_eq!(err.to_string(), shared.to_string());
}

#[test]
fn a_per_request_expiry_must_exist_and_be_near() {
    let (w, b) = (Node::new(), Node::new());
    let root = root_public_key(&w.public()).unwrap();
    let token = grant(&w, &b);
    let far = request(
        &token,
        &w,
        NOW + REQUEST_TOKEN_TTL_SECS + MAX_CLOCK_SKEW_SECS + 1,
        1,
        BINDING,
    );
    assert!(matches!(
        verify_request(&far, &check(&root, b.id(), TASK)),
        Err(TokenError::ExpiryOutOfWindow { .. })
    ));
    let edge = request(
        &token,
        &w,
        NOW + REQUEST_TOKEN_TTL_SECS + MAX_CLOCK_SKEW_SECS,
        1,
        BINDING,
    );
    verify_request(&edge, &check(&root, b.id(), TASK)).unwrap();
    let none = append_raw(
        &token,
        &w,
        &[
            &format!("nonce(\"{}\")", hex::encode([1u8; 16])),
            &format!("request_binding(\"{}\")", hex::encode(BINDING)),
        ],
        &[],
    );
    assert!(matches!(
        verify_request(&none, &check(&root, b.id(), TASK)),
        Err(TokenError::ExpiryOutOfWindow { .. })
    ));
}

#[test]
fn a_token_bound_to_another_request_is_refused() {
    let (w, b) = (Node::new(), Node::new());
    let root = root_public_key(&w.public()).unwrap();
    let token = grant(&w, &b);
    let for_x = request(&token, &w, NOW + 30, 1, [9; 32]);
    let err = verify_request(&for_x, &check(&root, b.id(), TASK)).unwrap_err();
    assert!(matches!(err, TokenError::BindingMismatch(_)), "{err}");
    // A second block cannot rebind it: every binding must match.
    let rebound = request(&for_x, &w, NOW + 30, 2, BINDING);
    assert!(matches!(
        verify_request(&rebound, &check(&root, b.id(), TASK)),
        Err(TokenError::BindingMismatch(_))
    ));
    let unbound = append_raw(
        &token,
        &w,
        &[
            &format!("expires({})", NOW + 30),
            &format!("nonce(\"{}\")", hex::encode([1u8; 16])),
        ],
        &[],
    );
    assert!(matches!(
        verify_request(&unbound, &check(&root, b.id(), TASK)),
        Err(TokenError::BindingMismatch(_))
    ));
}

#[test]
fn exactly_one_well_formed_nonce_is_required() {
    let (w, b) = (Node::new(), Node::new());
    let root = root_public_key(&w.public()).unwrap();
    let token = grant(&w, &b);
    let once = request(&token, &w, NOW + 30, 1, BINDING);
    let twice = request(&once, &w, NOW + 30, 2, BINDING);
    assert!(matches!(
        verify_request(&twice, &check(&root, b.id(), TASK)),
        Err(TokenError::BadNonce(_))
    ));
    let short = append_raw(
        &token,
        &w,
        &[
            &format!("expires({})", NOW + 30),
            "nonce(\"abcd\")",
            &format!("request_binding(\"{}\")", hex::encode(BINDING)),
        ],
        &[],
    );
    assert!(matches!(
        verify_request(&short, &check(&root, b.id(), TASK)),
        Err(TokenError::BadNonce(_))
    ));
}

#[test]
fn rules_checks_unknown_facts_and_widening_are_refused() {
    let (w, b, c) = (Node::new(), Node::new(), Node::new());
    let root = root_public_key(&w.public()).unwrap();
    let presented = request(&grant(&w, &b), &w, NOW + 30, 1, BINDING);
    for (facts, checks) in [
        (vec!["capability(\"mesh.admin\")"], vec![]),
        (vec![], vec!["check if time($t), $t < 2000-01-01T00:00:00Z"]),
        (vec!["colour(\"red\")"], vec![]),
    ] {
        let t = append_raw(&presented, &w, &facts, &checks);
        assert!(
            matches!(
                verify_request(&t, &check(&root, b.id(), TASK)),
                Err(TokenError::UnexpectedContent(_))
            ),
            "{facts:?} {checks:?}"
        );
    }
    let rebind = append_raw(
        &presented,
        &w,
        &[&format!("peer(\"{}\")", c.id().to_hex())],
        &[],
    );
    assert!(matches!(
        verify_request(&rebind, &check(&root, c.id(), TASK)),
        Err(TokenError::UnexpectedContent(_))
    ));
}

#[test]
fn the_gpu_job_template_restricts_to_gpu_tasks() {
    let (w, b) = (Node::new(), Node::new());
    let root = root_public_key(&w.public()).unwrap();
    let gpu = attenuate_gpu_job(&grant(&w, &b), &w.public(), Some(NOW + 600)).unwrap();
    verify_gpu_job(&gpu, &root, b.id(), NOW, true).unwrap();
    assert!(matches!(
        verify_gpu_job(&gpu, &root, b.id(), NOW, false),
        Err(TokenError::RestrictionNotMet(_))
    ));
    assert!(matches!(
        verify_gpu_job(&grant(&w, &b), &root, b.id(), NOW, true),
        Err(TokenError::CapabilityNotGranted(_))
    ));
    assert!(matches!(
        verify_gpu_job(&gpu, &root, b.id(), NOW + 600, true),
        Err(TokenError::Expired { .. })
    ));
    // Presented per request: a GPU task passes, the task path today (no
    // resource spec on the wire, so never a GPU task) and streams do not.
    let presented = request(&gpu, &w, NOW + 30, 1, BINDING);
    verify_request(
        &presented,
        &check(&root, b.id(), Operation::Task { requests_gpu: true }),
    )
    .unwrap();
    for op in [TASK, Operation::Stream] {
        assert!(matches!(
            verify_request(&presented, &check(&root, b.id(), op)),
            Err(TokenError::RestrictionNotMet(_))
        ));
    }
}

#[test]
fn the_agent_session_template_binds_one_session_with_a_short_expiry() {
    let (w, b) = (Node::new(), Node::new());
    let root = root_public_key(&w.public()).unwrap();
    let token = grant(&w, &b);
    let s = attenuate_agent_session(&token, &w.public(), "sess-1", NOW + 300, NOW).unwrap();
    verify_agent_session(&s, &root, b.id(), "sess-1", NOW).unwrap();
    assert!(matches!(
        verify_agent_session(&s, &root, b.id(), "sess-2", NOW),
        Err(TokenError::RestrictionNotMet(_))
    ));
    assert!(matches!(
        verify_agent_session(&token, &root, b.id(), "sess-1", NOW),
        Err(TokenError::CapabilityNotGranted(_))
    ));
    assert!(matches!(
        verify_agent_session(&s, &root, b.id(), "sess-1", NOW + 300),
        Err(TokenError::Expired { .. })
    ));
    for (id, exp) in [
        ("sess-1", NOW + 7_200),
        ("sess-1", NOW),
        ("bad id", NOW + 10),
        ("", NOW + 10),
    ] {
        assert!(matches!(
            attenuate_agent_session(&token, &w.public(), id, exp, NOW),
            Err(TokenError::Build(_))
        ));
    }
    let presented = request(&s, &w, NOW + 30, 1, BINDING);
    assert!(matches!(
        verify_request(&presented, &check(&root, b.id(), TASK)),
        Err(TokenError::RestrictionNotMet(_))
    ));
    verify_request(
        &presented,
        &check(&root, b.id(), Operation::AgentSession("sess-1")),
    )
    .unwrap();
}

/// The template promises a *short* expiry; a holder who bypasses the
/// builder (appending its own block) must not get a long-lived session.
#[test]
fn an_agent_session_expiry_beyond_the_template_cap_is_refused_by_the_verifier() {
    use entangle_biscuits::templates::AGENT_SESSION_MAX_TTL_SECS;
    let (w, b) = (Node::new(), Node::new());
    let root = root_public_key(&w.public()).unwrap();
    let token = grant(&w, &b);
    let ten_years = format!("expires({})", NOW + 10 * 365 * 24 * 3_600);
    let long = append_raw(
        &token,
        &w,
        &["agent_session(\"s1\")", ten_years.as_str()],
        &[],
    );
    assert!(
        matches!(
            verify_agent_session(&long, &root, b.id(), "s1", NOW),
            Err(TokenError::RestrictionNotMet(_))
        ),
        "an agent.session expiry ten years out must be refused"
    );
    // At the cap (plus the clock-skew allowance) it is still accepted.
    let at_cap = format!(
        "expires({})",
        NOW + AGENT_SESSION_MAX_TTL_SECS + MAX_CLOCK_SKEW_SECS
    );
    let ok = append_raw(&token, &w, &["agent_session(\"s1\")", at_cap.as_str()], &[]);
    verify_agent_session(&ok, &root, b.id(), "s1", NOW).unwrap();
    let over = format!(
        "expires({})",
        NOW + AGENT_SESSION_MAX_TTL_SECS + MAX_CLOCK_SKEW_SECS + 1
    );
    let over = append_raw(&token, &w, &["agent_session(\"s1\")", over.as_str()], &[]);
    assert!(matches!(
        verify_agent_session(&over, &root, b.id(), "s1", NOW),
        Err(TokenError::RestrictionNotMet(_))
    ));
}

#[test]
fn the_verifier_refuses_a_replayed_nonce() {
    let (w, b) = (Node::new(), Node::new());
    let v = RequestVerifier::new(&w.public()).unwrap();
    let token = grant(&w, &b);
    let first = request(&token, &w, NOW + 30, 1, BINDING);
    v.verify_at(&first, b.id(), BINDING, TASK, NOW).unwrap();
    assert_eq!(
        v.verify_at(&first, b.id(), BINDING, TASK, NOW),
        Err(TokenError::Replayed)
    );
    // Same nonce in a freshly attenuated token: still a replay.
    let again = request(&token, &w, NOW + 40, 1, BINDING);
    assert_eq!(
        v.verify_at(&again, b.id(), BINDING, TASK, NOW + 1),
        Err(TokenError::Replayed)
    );
    // A fresh nonce passes.
    v.verify_at(
        &request(&token, &w, NOW + 30, 2, BINDING),
        b.id(),
        BINDING,
        TASK,
        NOW,
    )
    .unwrap();
}

#[test]
fn the_verifier_refuses_a_revoked_token_and_fails_closed() {
    let (w, b) = (Node::new(), Node::new());
    let revoked = StaticRevocations::new();
    let v = RequestVerifier::new(&w.public())
        .unwrap()
        .with_revocations(Arc::new(revoked.clone()));
    let minted = mint_mesh_peer(&w.key, b.id(), None).unwrap();
    v.verify_at(
        &request(&minted.bytes, &w, NOW + 30, 1, BINDING),
        b.id(),
        BINDING,
        TASK,
        NOW,
    )
    .unwrap();
    revoked.revoke(minted.revocation_ids.clone());
    assert_eq!(
        v.verify_at(
            &request(&minted.bytes, &w, NOW + 30, 2, BINDING),
            b.id(),
            BINDING,
            TASK,
            NOW
        ),
        Err(TokenError::Revoked)
    );

    #[derive(Debug)]
    struct Broken;
    impl RevocationList for Broken {
        fn any_revoked(&self, _: &[Vec<u8>]) -> Result<bool, String> {
            Err("unreadable".into())
        }
    }
    let v = RequestVerifier::new(&w.public())
        .unwrap()
        .with_revocations(Arc::new(Broken));
    assert!(matches!(
        v.verify_at(
            &request(&minted.bytes, &w, NOW + 30, 3, BINDING),
            b.id(),
            BINDING,
            TASK,
            NOW
        ),
        Err(TokenError::RevocationsUnavailable(_))
    ));
}

#[test]
fn a_refused_token_takes_no_replay_slot() {
    let (w, b) = (Node::new(), Node::new());
    let v = RequestVerifier::new(&w.public())
        .unwrap()
        .with_replay_cache(ReplayCache::new(1, 1));
    let token = grant(&w, &b);
    // Bound to another request: refused before the cache.
    let wrong = request(&token, &w, NOW + 30, 1, [1; 32]);
    assert!(v.verify_at(&wrong, b.id(), BINDING, TASK, NOW).is_err());
    v.verify_at(
        &request(&token, &w, NOW + 30, 2, BINDING),
        b.id(),
        BINDING,
        TASK,
        NOW,
    )
    .unwrap();
}

#[test]
fn the_replay_cache_is_bounded_fails_closed_and_forgets_expired_nonces() {
    let (a, b) = (
        PeerId::from_public_key_bytes(&[1; 32]),
        PeerId::from_public_key_bytes(&[2; 32]),
    );
    let mut cache = ReplayCache::new(3, 2);
    cache.check_and_record([1; 16], a, NOW + 10, NOW).unwrap();
    cache.check_and_record([2; 16], a, NOW + 20, NOW).unwrap();
    assert!(
        matches!(
            cache.check_and_record([3; 16], a, NOW + 20, NOW),
            Err(TokenError::ReplayCacheFull(_))
        ),
        "per-peer bound"
    );
    cache.check_and_record([3; 16], b, NOW + 20, NOW).unwrap();
    assert!(
        matches!(
            cache.check_and_record([4; 16], b, NOW + 20, NOW),
            Err(TokenError::ReplayCacheFull(_))
        ),
        "global bound"
    );
    assert_eq!(cache.len(), 3);
    // Still within the grace period after the first expiry: kept.
    let grace = entangle_biscuits::templates::REPLAY_GRACE_SECS;
    assert_eq!(
        cache.check_and_record([1; 16], a, NOW + 10, NOW + 10 + grace - 1),
        Err(TokenError::Replayed)
    );
    // Past it: forgotten, and the slot is free again.
    cache
        .check_and_record([4; 16], b, NOW + 50, NOW + 10 + grace)
        .unwrap();
    assert_eq!(cache.len(), 3);
}

#[test]
fn every_template_error_carries_a_stable_code() {
    let w = Node::new();
    let root = root_public_key(&w.public()).unwrap();
    let err = verify_request(&[1, 2], &check(&root, w.id(), TASK)).unwrap_err();
    assert!(err.to_string().starts_with("ENTANGLE-E0451"));
    assert!(TokenError::Missing.to_string().contains("entangle pair"));
    assert!(TokenError::Revoked
        .to_string()
        .starts_with("ENTANGLE-E0460"));
}
