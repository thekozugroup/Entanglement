//! Integration tests for entangle-biscuits: roundtrip mint → verify scenarios.

use biscuit_auth::KeyPair;
use entangle_biscuits::{
    claims::ClaimSet, make_bridge_attenuation, mint, parse, verify, VerifyContext,
};
use entangle_types::peer_id::PeerId;

/// Fixed 32-byte public keys for stable test peer IDs.
const PEER_A_KEY: [u8; 32] = [0xAA; 32];
const PEER_B_KEY: [u8; 32] = [0xBB; 32];

fn peer_a() -> PeerId {
    PeerId::from_public_key_bytes(&PEER_A_KEY)
}

fn peer_b() -> PeerId {
    PeerId::from_public_key_bytes(&PEER_B_KEY)
}

fn now() -> i64 {
    // Fixed epoch for deterministic tests (2025-01-01 00:00:00 UTC).
    1_735_689_600
}

// ─── Test 1: happy path ───────────────────────────────────────────────────

#[test]
fn mint_then_verify_happy_path() {
    let kp = KeyPair::new();
    let pubkey = kp.public();

    let claims = ClaimSet::new()
        .issued_to(peer_a())
        .capability("compute.cpu")
        .expires(now() + 3_600);

    let bytes = mint(&kp, &claims).expect("mint ok");
    let biscuit = parse(&bytes, &pubkey).expect("parse ok");

    let ctx = VerifyContext {
        now_unix_secs: now(),
        local_peer_id: peer_a(),
    };
    let facts = verify(&biscuit, &ctx, "compute.cpu").expect("verify ok");

    assert!(
        facts.capabilities.contains(&"compute.cpu".to_string()),
        "expected compute.cpu in capabilities"
    );
}

// ─── Test 2: expired token ─────────────────────────────────────────────────

#[test]
fn expired_token_rejected() {
    let kp = KeyPair::new();
    let pubkey = kp.public();

    let claims = ClaimSet::new()
        .capability("compute.cpu")
        .expires(now() - 60); // 60 seconds in the past

    let bytes = mint(&kp, &claims).expect("mint ok");
    let biscuit = parse(&bytes, &pubkey).expect("parse ok");

    let ctx = VerifyContext {
        now_unix_secs: now(),
        local_peer_id: peer_a(),
    };
    let result = verify(&biscuit, &ctx, "compute.cpu");

    assert!(result.is_err(), "expired token should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("expired") || err.contains("E0412"),
        "unexpected error: {err}"
    );
}

// ─── Test 3: wrong peer ────────────────────────────────────────────────────

#[test]
fn wrong_peer_rejected() {
    let kp = KeyPair::new();
    let pubkey = kp.public();

    let claims = ClaimSet::new()
        .issued_to(peer_a())
        .capability("compute.cpu")
        .expires(now() + 3_600);

    let bytes = mint(&kp, &claims).expect("mint ok");
    let biscuit = parse(&bytes, &pubkey).expect("parse ok");

    // Verify as peer_b — should fail because the token is issued_to peer_a.
    let ctx = VerifyContext {
        now_unix_secs: now(),
        local_peer_id: peer_b(),
    };
    let result = verify(&biscuit, &ctx, "compute.cpu");

    assert!(result.is_err(), "wrong-peer token should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("peer") || err.contains("E0412"),
        "unexpected error: {err}"
    );
}

// ─── Test 4: missing required capability ──────────────────────────────────

#[test]
fn missing_required_capability_rejected() {
    let kp = KeyPair::new();
    let pubkey = kp.public();

    let claims = ClaimSet::new()
        .capability("compute.cpu")
        .expires(now() + 3_600);

    let bytes = mint(&kp, &claims).expect("mint ok");
    let biscuit = parse(&bytes, &pubkey).expect("parse ok");

    let ctx = VerifyContext {
        now_unix_secs: now(),
        local_peer_id: peer_a(),
    };
    // Token has "compute.cpu" but verifier requires "host.docker-socket"
    let result = verify(&biscuit, &ctx, "host.docker-socket");

    assert!(result.is_err(), "missing capability should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("capability") || err.contains("E0412"),
        "unexpected error: {err}"
    );
}

// ─── Test 5: attenuation + bridge facts extraction ────────────────────────

#[test]
fn attenuate_with_bridge_facts_extracts_5() {
    use entangle_biscuits::mint::attenuate_biscuit;

    let kp = KeyPair::new();
    let pubkey = kp.public();

    // Mint a base cap for peer_a.
    let base_claims = ClaimSet::new()
        .issued_to(peer_a())
        .capability("compute.gpu")
        .expires(now() + 3_600);

    let base_bytes = mint(&kp, &base_claims).expect("base mint ok");

    // Attenuate with bridge facts.
    let bridge_claims = make_bridge_attenuation(
        peer_b(),      // dest_pin
        10_000_000,    // 10 MiB/s rate limit
        1_000_000_000, // 1 GiB total
        now() + 1_800, // expires in 30 min (within 1h bridge TTL)
    );

    let attenuated =
        attenuate_biscuit(&base_bytes, &pubkey, &bridge_claims).expect("attenuation ok");

    let biscuit = parse(&attenuated, &pubkey).expect("parse ok");

    let ctx = VerifyContext {
        now_unix_secs: now(),
        local_peer_id: peer_a(),
    };
    let facts = verify(&biscuit, &ctx, "compute.gpu").expect("verify ok");

    // All 5 bridge fields must be populated.
    assert!(facts.dest_pin.is_some(), "dest_pin should be extracted");
    assert!(
        facts.rate_limit_bps.is_some(),
        "rate_limit_bps should be extracted"
    );
    assert!(
        facts.total_bytes_cap.is_some(),
        "total_bytes_cap should be extracted"
    );
    assert!(facts.bridge_marker, "bridge marker should be true");
    assert!(facts.expires.is_some(), "expires should be extracted");

    assert_eq!(facts.dest_pin.unwrap(), peer_b());
    assert_eq!(facts.rate_limit_bps.unwrap(), 10_000_000);
    assert_eq!(facts.total_bytes_cap.unwrap(), 1_000_000_000);
}
