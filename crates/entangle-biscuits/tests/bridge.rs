//! ATC-BRG-* acceptance tests for bridge cap attenuation rules (spec §6.4, §16).

use biscuit_auth::KeyPair;
use entangle_biscuits::{
    attenuate_biscuit,
    bridge::{BridgeError, BridgeVerifyContext, BRIDGE_RATE_LIMIT_MAX_BPS},
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

/// ATC-BRG-1: Happy path — fully-attenuated bridge cap is accepted.
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

// ─── ATC-BRG-2 ───────────────────────────────────────────────────────────────

/// ATC-BRG-2: Missing dest_pin → AttenuationMissing("dest_pin").
#[test]
fn atc_brg_2_missing_dest_pin_rejected() {
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

// ─── ATC-BRG-3 ───────────────────────────────────────────────────────────────

/// ATC-BRG-3: Missing rate_limit_bps → AttenuationMissing("rate_limit_bps").
#[test]
fn atc_brg_3_missing_rate_limit_rejected() {
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

// ─── ATC-BRG-4 ───────────────────────────────────────────────────────────────

/// ATC-BRG-4: Missing total_bytes_cap → AttenuationMissing("total_bytes_cap").
#[test]
fn atc_brg_4_missing_total_bytes_rejected() {
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

// ─── ATC-BRG-5 ───────────────────────────────────────────────────────────────

/// ATC-BRG-5: Missing expires → AttenuationMissing("expires").
#[test]
fn atc_brg_5_missing_expires_rejected() {
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

// ─── ATC-BRG-6 ───────────────────────────────────────────────────────────────

/// ATC-BRG-6: Missing bridge(true) marker → AttenuationMissing("bridge(true)").
#[test]
fn atc_brg_6_missing_bridge_marker_rejected() {
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

// ─── ATC-BRG-7 ───────────────────────────────────────────────────────────────

/// ATC-BRG-7: expires = now + 7200 (2 hours) → TtlTooLong.
#[test]
fn atc_brg_7_ttl_over_one_hour_rejected() {
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

// ─── ATC-BRG-8 ───────────────────────────────────────────────────────────────

/// ATC-BRG-8: rate_limit_bps = max + 1 → RateLimitTooHigh.
#[test]
fn atc_brg_8_rate_limit_over_max_rejected() {
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

// ─── ATC-BRG-9 ───────────────────────────────────────────────────────────────

/// ATC-BRG-9: dest_pin = PEER_A; verify with expected_destination = PEER_B → DestPinMismatch.
#[test]
fn atc_brg_9_dest_pin_mismatch_rejected() {
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

// ─── ATC-BRG-10 ──────────────────────────────────────────────────────────────

/// ATC-BRG-10: require_capability = "compute.gpu"; cap minted with "compute.gpu" → passes.
#[test]
fn atc_brg_10_capability_required_passes_through() {
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
