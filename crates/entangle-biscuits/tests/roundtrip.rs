//! Integration tests for entangle-biscuits: roundtrip mint → verify scenarios.

use biscuit_auth::PrivateKey;
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
    let kp = PrivateKey::new();
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
        facts
            .authority_capabilities
            .contains(&"compute.cpu".to_string()),
        "expected compute.cpu in authority capabilities"
    );
}

// ─── Test 2: expired token ─────────────────────────────────────────────────

#[test]
fn expired_token_rejected() {
    let kp = PrivateKey::new();
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
    let kp = PrivateKey::new();
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
    let kp = PrivateKey::new();
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

    let kp = PrivateKey::new();
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

#[test]
fn signed_datalog_checks_must_be_satisfied() {
    use biscuit_auth::builder::BlockBuilder;

    let signer = PrivateKey::new();
    let bytes = mint(
        &signer,
        &ClaimSet::new()
            .issued_to(peer_a())
            .capability("compute.cpu"),
    )
    .expect("mint");
    let base = parse(&bytes, &signer.public()).unwrap();
    let ctx = VerifyContext {
        now_unix_secs: now(),
        local_peer_id: peer_a(),
    };

    for (query, allowed) in [
        (r#"check if capability("compute.cpu")"#, true),
        (r#"check if capability("compute.gpu")"#, false),
        (r#"check if licensed("worker")"#, false),
    ] {
        let restricted = base
            .append(BlockBuilder::new().check(query).unwrap())
            .unwrap();
        let token = parse(&restricted.to_vec().unwrap(), &signer.public()).unwrap();
        assert_eq!(
            verify(&token, &ctx, "compute.cpu").is_ok(),
            allowed,
            "{query}"
        );
    }
}

/// Public test vectors minted by the unmodified stable 6.0.0 library.
/// The fixed verification times precede and coincide with their expiry.
#[test]
fn reads_v6_ed25519_and_p256_tokens_and_enforces_their_checks() {
    let vectors: [(&str, &[u8], &[u8]); 2] = [
        (
            include_str!("fixtures/v6/ed25519-public.pem.txt"),
            include_bytes!("fixtures/v6/ed25519-allowed.biscuit"),
            include_bytes!("fixtures/v6/ed25519-denied.biscuit"),
        ),
        (
            include_str!("fixtures/v6/p256-public.pem.txt"),
            include_bytes!("fixtures/v6/p256-allowed.biscuit"),
            include_bytes!("fixtures/v6/p256-denied.biscuit"),
        ),
    ];
    let peer = PeerId::from_public_key_bytes(&[3; 32]);
    let ctx = VerifyContext {
        now_unix_secs: 2,
        local_peer_id: peer,
    };
    let expired = VerifyContext {
        now_unix_secs: 1000,
        local_peer_id: peer,
    };
    for (pem, allowed, denied) in vectors {
        let signer = biscuit_auth::PublicKey::from_pem(pem).unwrap();
        let allowed = parse(allowed, &signer).unwrap();
        verify(&allowed, &ctx, "compute.cpu").unwrap();
        assert!(verify(&allowed, &ctx, "compute.gpu").is_err());
        assert!(verify(&allowed, &expired, "compute.cpu").is_err());
        let denied = parse(denied, &signer).unwrap();
        assert!(verify(&denied, &ctx, "compute.cpu").is_err());
    }
}
