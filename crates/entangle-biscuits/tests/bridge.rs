//! ATC-BRG-1..6 acceptance tests for bridge cap attenuation rules (spec §6.4, §16,
//! docs/architecture.md §16.3). The `atc_brg_<n>_` prefix is reserved for the six
//! spec propositions:
//!
//! - ATC-BRG-1 valid bridge accepted                 → `atc_brg_1_full_attenuation_accepted`
//! - ATC-BRG-2 missing rate_limit rejected           → `atc_brg_2_missing_rate_limit_rejected`
//! - ATC-BRG-3 pinned to X, verified by Y, rejected  → `atc_brg_3_dest_pin_mismatch_rejected`
//! - ATC-BRG-4 elapsed expiry rejected               → `atc_brg_4_expired_ttl_rejected`
//! - ATC-BRG-5 missing total_bytes_cap rejected      → `atc_brg_5_missing_total_bytes_cap_rejected`
//! - ATC-BRG-6 cumulative byte cap enforced          → `atc_brg_6_cumulative_byte_cap_enforced`
//!
//! Tests without an `atc_` prefix check other real bridge behaviour that has no
//! spec ID of its own.

use biscuit_auth::KeyPair;
use entangle_biscuits::errors::BiscuitError;
use entangle_biscuits::{
    attenuate_biscuit,
    bridge::{BridgeBudget, BridgeError, BridgeVerifyContext, BRIDGE_RATE_LIMIT_MAX_BPS},
    claims::ClaimSet,
    make_bridge_attenuation, mint, verify_bridge_cap,
};
use entangle_types::peer_id::PeerId;

// ─── Test fixtures ───────────────────────────────────────────────────────────

fn root_keypair() -> KeyPair {
    KeyPair::new()
}

/// A deterministic peer derived from a fixed byte pattern.
fn peer(seed: u8) -> PeerId {
    PeerId::from_public_key_bytes(&[seed; 32])
}

const NOW: i64 = 1_000_000;
const GOOD_EXPIRES: i64 = NOW + 1_800; // 30 min — within 1-hour ceiling
const CAP: &str = "compute.gpu";

/// Mint a base capability biscuit (authority block only).
fn base_biscuit(kp: &KeyPair, _dest: PeerId) -> Vec<u8> {
    // Bridge base tokens do not carry `issued_to`; destination binding is
    // enforced by the `dest_pin` attenuation fact (spec §6.4).
    let claims = ClaimSet::new().capability(CAP);
    mint(kp, &claims).expect("mint must succeed")
}

/// Build a full bridge-attenuated biscuit.
fn full_bridge_biscuit(
    base: &[u8],
    kp: &KeyPair,
    dest: PeerId,
    expires: i64,
    rate_bps: u64,
    total_bytes: u64,
) -> Vec<u8> {
    let attn = make_bridge_attenuation(dest, rate_bps, total_bytes, expires);
    attenuate_biscuit(base, &kp.public(), &attn).expect("attenuate must succeed")
}

fn bridge_ctx(dest: PeerId) -> BridgeVerifyContext {
    BridgeVerifyContext {
        now_unix_secs: NOW,
        local_peer_id: peer(0xAA),
        expected_destination: dest,
        require_capability: CAP.into(),
    }
}

// ─── ATC-BRG-1 ───────────────────────────────────────────────────────────────

/// ATC-BRG-1: fully-attenuated bridge cap (all 5 facts) is accepted.
#[test]
fn atc_brg_1_full_attenuation_accepted() {
    let kp = root_keypair();
    let dest = peer(0x01);
    let base = base_biscuit(&kp, dest);
    let attenuated = full_bridge_biscuit(&base, &kp, dest, GOOD_EXPIRES, 1_000_000, 10_000_000);

    let facts = verify_bridge_cap(&attenuated, &kp.public(), &bridge_ctx(dest))
        .expect("full bridge cap must verify");

    assert!(facts.capabilities.contains(&CAP.to_string()));
    assert_eq!(facts.dest_pin, dest);
    assert_eq!(facts.rate_limit_bps, 1_000_000);
    assert_eq!(facts.total_bytes_cap, 10_000_000);
    assert_eq!(facts.expires, GOOD_EXPIRES);
}

/// Missing dest_pin → AttenuationMissing("dest_pin").
#[test]
fn bridge_missing_dest_pin_rejected() {
    let kp = root_keypair();
    let dest = peer(0x02);
    let base = base_biscuit(&kp, dest);

    // Attenuation without dest_pin
    let attn = ClaimSet::new()
        .rate_limit_bps(1_000_000)
        .total_bytes_cap(10_000_000)
        .expires(GOOD_EXPIRES)
        .bridge_marker();
    let token = attenuate_biscuit(&base, &kp.public(), &attn).unwrap();

    let err = verify_bridge_cap(&token, &kp.public(), &bridge_ctx(dest)).unwrap_err();
    assert!(
        matches!(err, BridgeError::AttenuationMissing("dest_pin")),
        "expected AttenuationMissing(dest_pin), got: {err}"
    );
}

// ─── ATC-BRG-2 ───────────────────────────────────────────────────────────────

/// ATC-BRG-2: missing rate_limit_bps → AttenuationMissing("rate_limit_bps").
#[test]
fn atc_brg_2_missing_rate_limit_rejected() {
    let kp = root_keypair();
    let dest = peer(0x03);
    let base = base_biscuit(&kp, dest);

    let attn = ClaimSet::new()
        .dest_pin(dest)
        .total_bytes_cap(10_000_000)
        .expires(GOOD_EXPIRES)
        .bridge_marker();
    let token = attenuate_biscuit(&base, &kp.public(), &attn).unwrap();

    let err = verify_bridge_cap(&token, &kp.public(), &bridge_ctx(dest)).unwrap_err();
    assert!(
        matches!(err, BridgeError::AttenuationMissing("rate_limit_bps")),
        "expected AttenuationMissing(rate_limit_bps), got: {err}"
    );
}

// ─── ATC-BRG-5 ───────────────────────────────────────────────────────────────

/// ATC-BRG-5: missing total_bytes_cap → AttenuationMissing("total_bytes_cap").
#[test]
fn atc_brg_5_missing_total_bytes_cap_rejected() {
    let kp = root_keypair();
    let dest = peer(0x04);
    let base = base_biscuit(&kp, dest);

    let attn = ClaimSet::new()
        .dest_pin(dest)
        .rate_limit_bps(1_000_000)
        .expires(GOOD_EXPIRES)
        .bridge_marker();
    let token = attenuate_biscuit(&base, &kp.public(), &attn).unwrap();

    let err = verify_bridge_cap(&token, &kp.public(), &bridge_ctx(dest)).unwrap_err();
    assert!(
        matches!(err, BridgeError::AttenuationMissing("total_bytes_cap")),
        "expected AttenuationMissing(total_bytes_cap), got: {err}"
    );
}

/// Missing expires → AttenuationMissing("expires").
#[test]
fn bridge_missing_expires_rejected() {
    let kp = root_keypair();
    let dest = peer(0x05);
    let base = base_biscuit(&kp, dest);

    let attn = ClaimSet::new()
        .dest_pin(dest)
        .rate_limit_bps(1_000_000)
        .total_bytes_cap(10_000_000)
        .bridge_marker();
    let token = attenuate_biscuit(&base, &kp.public(), &attn).unwrap();

    let err = verify_bridge_cap(&token, &kp.public(), &bridge_ctx(dest)).unwrap_err();
    assert!(
        matches!(err, BridgeError::AttenuationMissing("expires")),
        "expected AttenuationMissing(expires), got: {err}"
    );
}

/// Missing bridge(true) marker → AttenuationMissing("bridge(true)").
#[test]
fn bridge_missing_bridge_marker_rejected() {
    let kp = root_keypair();
    let dest = peer(0x06);
    let base = base_biscuit(&kp, dest);

    let attn = ClaimSet::new()
        .dest_pin(dest)
        .rate_limit_bps(1_000_000)
        .total_bytes_cap(10_000_000)
        .expires(GOOD_EXPIRES);
    // No .bridge_marker()
    let token = attenuate_biscuit(&base, &kp.public(), &attn).unwrap();

    let err = verify_bridge_cap(&token, &kp.public(), &bridge_ctx(dest)).unwrap_err();
    assert!(
        matches!(err, BridgeError::AttenuationMissing("bridge(true)")),
        "expected AttenuationMissing(bridge(true)), got: {err}"
    );
}

/// expires = now + 7200 (2 hours) → TtlTooLong.
#[test]
fn bridge_ttl_over_one_hour_rejected() {
    let kp = root_keypair();
    let dest = peer(0x07);
    let base = base_biscuit(&kp, dest);
    let two_hours = NOW + 7_200;

    let token = full_bridge_biscuit(&base, &kp, dest, two_hours, 1_000_000, 10_000_000);

    let err = verify_bridge_cap(&token, &kp.public(), &bridge_ctx(dest)).unwrap_err();
    assert!(
        matches!(
            err,
            BridgeError::TtlTooLong {
                ttl: 7_200,
                max: 3_600
            }
        ),
        "expected TtlTooLong, got: {err}"
    );
}

/// rate_limit_bps = max + 1 → RateLimitTooHigh.
#[test]
fn bridge_rate_limit_over_max_rejected() {
    let kp = root_keypair();
    let dest = peer(0x08);
    let base = base_biscuit(&kp, dest);
    let over_limit = BRIDGE_RATE_LIMIT_MAX_BPS + 1;

    let token = full_bridge_biscuit(&base, &kp, dest, GOOD_EXPIRES, over_limit, 10_000_000);

    let err = verify_bridge_cap(&token, &kp.public(), &bridge_ctx(dest)).unwrap_err();
    assert!(
        matches!(err, BridgeError::RateLimitTooHigh { .. }),
        "expected RateLimitTooHigh, got: {err}"
    );
}

// ─── ATC-BRG-3 ───────────────────────────────────────────────────────────────

/// ATC-BRG-3: dest_pin = PEER_A; verify with expected_destination = PEER_B → DestPinMismatch.
#[test]
fn atc_brg_3_dest_pin_mismatch_rejected() {
    let kp = root_keypair();
    let peer_a = peer(0x0A);
    let peer_b = peer(0x0B);
    let base = base_biscuit(&kp, peer_a);

    // Pin to peer_a
    let token = full_bridge_biscuit(&base, &kp, peer_a, GOOD_EXPIRES, 1_000_000, 10_000_000);

    // Verify expecting peer_b
    let mut ctx = bridge_ctx(peer_a);
    ctx.expected_destination = peer_b;

    let err = verify_bridge_cap(&token, &kp.public(), &ctx).unwrap_err();
    assert!(
        matches!(err, BridgeError::DestPinMismatch { .. }),
        "expected DestPinMismatch, got: {err}"
    );
}

// ─── Capability pass-through ─────────────────────────────────────────────────

/// require_capability = "compute.gpu"; cap minted with "compute.gpu" → passes.
#[test]
fn bridge_capability_required_passes_through() {
    let kp = root_keypair();
    let dest = peer(0x0C);

    // Mint with compute.gpu — no issued_to for bridge tokens (dest_pin handles that)
    let claims = ClaimSet::new().capability("compute.gpu");
    let base = mint(&kp, &claims).unwrap();

    let token = full_bridge_biscuit(&base, &kp, dest, GOOD_EXPIRES, 1_000_000, 10_000_000);

    let ctx = BridgeVerifyContext {
        now_unix_secs: NOW,
        local_peer_id: peer(0xAA),
        expected_destination: dest,
        require_capability: "compute.gpu".into(),
    };

    let facts =
        verify_bridge_cap(&token, &kp.public(), &ctx).expect("compute.gpu cap must pass through");
    assert!(facts.capabilities.contains(&"compute.gpu".to_string()));
}

// ─── ATC-BRG-4 ───────────────────────────────────────────────────────────────

/// ATC-BRG-4: fully-attenuated bridge whose expiry is in the past at verification
/// time is rejected. Expiry is enforced by the shared biscuit verifier
/// (`verifier::verify`, `now >= expires`), which runs before the bridge checks, so
/// the rejection surfaces as `BridgeError::Biscuit(BiscuitError::Verify(..))`
/// (ENTANGLE-E0412), not a bridge-specific code.
#[test]
fn atc_brg_4_expired_ttl_rejected() {
    let kp = root_keypair();
    let dest = peer(0x0D);
    let base = base_biscuit(&kp, dest);
    // Every other attenuation is valid; only the expiry has elapsed.
    let expired_at = NOW - 1;

    let token = full_bridge_biscuit(&base, &kp, dest, expired_at, 1_000_000, 10_000_000);

    let err = verify_bridge_cap(&token, &kp.public(), &bridge_ctx(dest)).unwrap_err();
    match &err {
        BridgeError::Biscuit(BiscuitError::Verify(msg)) => {
            assert!(msg.contains("expired"), "unexpected verify message: {msg}");
        }
        other => panic!("expected expiry rejection, got: {other}"),
    }
}

// ─── ATC-BRG-6 ───────────────────────────────────────────────────────────────

/// ATC-BRG-6: with total_bytes_cap = 1024, relaying 1024 bytes succeeds and one
/// further byte is rejected with BridgeBudgetExhausted (ENTANGLE-E0425).
#[test]
fn atc_brg_6_cumulative_byte_cap_enforced() {
    let kp = root_keypair();
    let dest = peer(0x0E);
    let base = base_biscuit(&kp, dest);
    let token = full_bridge_biscuit(&base, &kp, dest, GOOD_EXPIRES, 1_000_000, 1024);

    let facts =
        verify_bridge_cap(&token, &kp.public(), &bridge_ctx(dest)).expect("bridge cap must verify");
    let budget = BridgeBudget::from_facts(&facts);

    budget
        .try_consume(1024)
        .expect("first 1024 bytes are within the cap");
    let err = budget.try_consume(1).unwrap_err();
    assert!(
        matches!(
            err,
            BridgeError::BridgeBudgetExhausted {
                cap: 1024,
                used: 1024,
                requested: 1
            }
        ),
        "expected BridgeBudgetExhausted, got: {err}"
    );
    assert!(err.to_string().starts_with("ENTANGLE-E0425"));
}

// ─── BridgeBudget unit behaviour ─────────────────────────────────────────────

#[test]
fn budget_exact_boundary_accepted_then_refused() {
    let budget = BridgeBudget::new(10);
    budget.try_consume(4).unwrap();
    budget
        .try_consume(6)
        .expect("landing exactly on the cap is allowed");
    assert_eq!(budget.used(), 10);
    assert_eq!(budget.remaining(), 0);
    assert!(budget.try_consume(1).is_err());
}

#[test]
fn budget_zero_byte_consume_always_succeeds() {
    let budget = BridgeBudget::new(0);
    budget
        .try_consume(0)
        .expect("zero bytes never exceed a zero cap");
    assert_eq!(budget.used(), 0);

    let full = BridgeBudget::new(5);
    full.try_consume(5).unwrap();
    full.try_consume(0)
        .expect("zero bytes succeed even when exhausted");
    assert_eq!(full.used(), 5);
}

#[test]
fn budget_overflow_attempt_refused_without_consuming() {
    let budget = BridgeBudget::new(u64::MAX);
    budget.try_consume(10).unwrap();

    let err = budget.try_consume(u64::MAX).unwrap_err();
    assert!(
        matches!(
            err,
            BridgeError::BridgeBudgetExhausted { used: 10, requested, .. } if requested == u64::MAX
        ),
        "expected overflow to be refused, got: {err}"
    );
    // Refused request must not partially consume.
    assert_eq!(budget.used(), 10);
    budget
        .try_consume(u64::MAX - 10)
        .expect("exact remainder fits");
    assert_eq!(budget.remaining(), 0);
}

#[test]
fn budget_refused_request_does_not_partially_consume() {
    let budget = BridgeBudget::new(100);
    budget.try_consume(90).unwrap();
    assert!(budget.try_consume(11).is_err());
    assert_eq!(
        budget.used(),
        90,
        "a refused consume must leave the counter unchanged"
    );
    budget
        .try_consume(10)
        .expect("the remaining 10 bytes are still available");
}

#[test]
fn budget_many_small_consumes_sum_to_cap() {
    let budget = BridgeBudget::new(1_000);
    for _ in 0..1_000 {
        budget.try_consume(1).expect("each 1-byte chunk fits");
    }
    assert_eq!(budget.used(), 1_000);
    assert!(budget.try_consume(1).is_err());
}

#[test]
fn budget_is_shared_safely_across_threads() {
    use std::sync::Arc;

    let budget = Arc::new(BridgeBudget::new(10_000));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let b = Arc::clone(&budget);
            std::thread::spawn(move || {
                let mut ok = 0u64;
                for _ in 0..5_000 {
                    if b.try_consume(1).is_ok() {
                        ok += 1;
                    }
                }
                ok
            })
        })
        .collect();
    let granted: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(
        granted, 10_000,
        "exactly the cap is granted across all threads"
    );
    assert_eq!(budget.used(), 10_000);
}
