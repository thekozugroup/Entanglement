//! Regression tests: grant-conferring facts are confined to the authority
//! block (spec §6.4, SECURITY.md "attenuation can only narrow").
//!
//! A token holder can always append attenuation blocks — they are signed by
//! fresh ephemeral keys, not the root key. The verifier must therefore never
//! honor a `capability(...)` or `peer(...)` fact from an appended block, and
//! must merge restriction facts tightest-wins so an appended block can only
//! narrow the grant.

use biscuit_auth::KeyPair;
use entangle_biscuits::{
    attenuate_biscuit, claims::ClaimSet, make_bridge_attenuation, mint, parse, verify,
    verify_bridge_cap, BiscuitError, BridgeVerifyContext, VerifyContext,
};
use entangle_types::peer_id::PeerId;

fn peer(seed: u8) -> PeerId {
    PeerId::from_public_key_bytes(&[seed; 32])
}

const NOW: i64 = 1_735_689_600; // 2025-01-01 00:00:00 UTC

fn ctx(local: PeerId) -> VerifyContext {
    VerifyContext {
        now_unix_secs: NOW,
        local_peer_id: local,
    }
}

// ─── (a) appended capability is not granted ────────────────────────────────

#[test]
fn appended_capability_is_not_granted() {
    let kp = KeyPair::new();
    let pubkey = kp.public();

    // Authority grants only compute.cpu to peer A.
    let base = mint(
        &kp,
        &ClaimSet::new()
            .issued_to(peer(0xAA))
            .capability("compute.cpu")
            .expires(NOW + 3_600),
    )
    .expect("mint ok");

    // Attacker (any token holder) appends a block claiming a new capability.
    let escalated = attenuate_biscuit(
        &base,
        &pubkey,
        &ClaimSet::new().capability("host.docker-socket"),
    )
    .expect("attenuation ok");

    let biscuit = parse(&escalated, &pubkey).expect("parse ok");
    let err = verify(&biscuit, &ctx(peer(0xAA)), "host.docker-socket")
        .expect_err("appended capability must NOT be granted");
    assert!(
        matches!(err, BiscuitError::Verify(_)),
        "expected Verify error, got: {err}"
    );
    assert!(
        err.to_string().contains("capability"),
        "error should mention the capability confinement violation: {err}"
    );

    // Even the legitimately-granted capability is refused on a tampered
    // token: the widening attempt poisons the whole token.
    verify(&biscuit, &ctx(peer(0xAA)), "compute.cpu")
        .expect_err("token with a widening block must be rejected outright");
}

// ─── (b) appended peer fact cannot rebind the token ────────────────────────

#[test]
fn appended_peer_cannot_rebind() {
    let kp = KeyPair::new();
    let pubkey = kp.public();

    // Authority binds the token to peer A.
    let base = mint(
        &kp,
        &ClaimSet::new()
            .issued_to(peer(0xAA))
            .capability("compute.cpu")
            .expires(NOW + 3_600),
    )
    .expect("mint ok");

    // Attacker appends peer(B), attempting to make the token verify on B.
    let rebound = attenuate_biscuit(&base, &pubkey, &ClaimSet::new().issued_to(peer(0xBB)))
        .expect("attenuation ok");

    let biscuit = parse(&rebound, &pubkey).expect("parse ok");
    let err = verify(&biscuit, &ctx(peer(0xBB)), "compute.cpu")
        .expect_err("appended peer fact must not rebind the token");
    assert!(
        matches!(err, BiscuitError::Verify(_)),
        "expected Verify error, got: {err}"
    );
    assert!(
        err.to_string().contains("peer"),
        "error should mention the peer confinement violation: {err}"
    );

    // The original holder is also refused: a tampered token is dead.
    verify(&biscuit, &ctx(peer(0xAA)), "compute.cpu")
        .expect_err("token with a rebinding block must be rejected outright");
}

// ─── (c) appended rate_limit_bps cannot RAISE the bridge limit ─────────────

#[test]
fn appended_rate_limit_cannot_raise_bridge_limit() {
    let kp = KeyPair::new();
    let pubkey = kp.public();
    let dest = peer(0x01);

    let base = mint(&kp, &ClaimSet::new().capability("compute.gpu")).expect("mint ok");

    // Legitimate bridge attenuation: 1 MB/s.
    let bridged = attenuate_biscuit(
        &base,
        &pubkey,
        &make_bridge_attenuation(dest, 1_000_000, 10_000_000, NOW + 1_800),
    )
    .expect("bridge attenuation ok");

    // Attacker appends a much higher rate limit, trying to raise the cap.
    let raised = attenuate_biscuit(
        &bridged,
        &pubkey,
        &ClaimSet::new().rate_limit_bps(500_000_000),
    )
    .expect("attenuation ok");

    let bridge_ctx = BridgeVerifyContext {
        now_unix_secs: NOW,
        local_peer_id: peer(0xAA),
        expected_destination: dest,
        require_capability: "compute.gpu".into(),
    };
    let facts = verify_bridge_cap(&raised, &pubkey, &bridge_ctx).expect("verify ok");
    assert_eq!(
        facts.rate_limit_bps, 1_000_000,
        "tightest rate limit must win; an appended block cannot raise it"
    );
    assert_eq!(
        facts.total_bytes_cap, 10_000_000,
        "total_bytes_cap must be unchanged"
    );
}

// ─── (d) appended expires yields the tighter authority expiry ──────────────

#[test]
fn appended_expires_keeps_tighter_authority_expiry() {
    let kp = KeyPair::new();
    let pubkey = kp.public();

    // Authority expires in 100s.
    let base = mint(
        &kp,
        &ClaimSet::new()
            .issued_to(peer(0xAA))
            .capability("compute.cpu")
            .expires(NOW + 100),
    )
    .expect("mint ok");

    // Attacker appends a looser expiry (1 hour), trying to extend the token.
    let extended = attenuate_biscuit(&base, &pubkey, &ClaimSet::new().expires(NOW + 3_600))
        .expect("attenuation ok");

    let biscuit = parse(&extended, &pubkey).expect("parse ok");
    let facts = verify(&biscuit, &ctx(peer(0xAA)), "compute.cpu").expect("verify ok");
    assert_eq!(
        facts.expires,
        Some(NOW + 100),
        "the tighter authority expiry must win"
    );

    // And past the authority expiry the token is dead, regardless of the
    // appended looser expiry.
    let late_ctx = VerifyContext {
        now_unix_secs: NOW + 200,
        local_peer_id: peer(0xAA),
    };
    verify(&biscuit, &late_ctx, "compute.cpu")
        .expect_err("token must be expired past the authority expiry");
}

// ─── extra: appended dest_pin cannot re-pin the destination ────────────────

#[test]
fn appended_dest_pin_cannot_repin_destination() {
    let kp = KeyPair::new();
    let pubkey = kp.public();
    let dest = peer(0x01);
    let attacker_dest = peer(0x02);

    let base = mint(&kp, &ClaimSet::new().capability("compute.gpu")).expect("mint ok");
    let bridged = attenuate_biscuit(
        &base,
        &pubkey,
        &make_bridge_attenuation(dest, 1_000_000, 10_000_000, NOW + 1_800),
    )
    .expect("bridge attenuation ok");

    // Attacker appends a different dest_pin, trying to re-route the relay.
    let repinned = attenuate_biscuit(&bridged, &pubkey, &ClaimSet::new().dest_pin(attacker_dest))
        .expect("attenuation ok");

    // Verifying for the attacker's destination must fail: first pin wins.
    let mut bridge_ctx = BridgeVerifyContext {
        now_unix_secs: NOW,
        local_peer_id: peer(0xAA),
        expected_destination: attacker_dest,
        require_capability: "compute.gpu".into(),
    };
    verify_bridge_cap(&repinned, &pubkey, &bridge_ctx)
        .expect_err("appended dest_pin must not re-route the bridge");

    // The original destination still verifies.
    bridge_ctx.expected_destination = dest;
    let facts = verify_bridge_cap(&repinned, &pubkey, &bridge_ctx).expect("verify ok");
    assert_eq!(facts.dest_pin, dest, "first-written dest_pin must win");
}
