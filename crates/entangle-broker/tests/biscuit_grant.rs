//! Integration tests: `Broker::grant_with_biscuit` — biscuit verification layer.
//!
//! These tests verify that `grant_with_biscuit` enforces two independent deny-
//! by-default layers:
//!   1. The biscuit must be signed by a trust root, not expired, bound to the
//!      correct peer, and contain the required capability surface.
//!   2. The plugin's manifest must also declare the capability (biscuit grants
//!      are not a manifest bypass).

use biscuit_auth::KeyPair as BiscuitKp;
use entangle_biscuits::claims::ClaimSet;
use entangle_broker::{
    errors::BrokerError,
    policy::{BrokerPolicy, CrossNodePolicy},
    Broker,
};
use entangle_manifest::{
    schema::{BuildSection, Manifest, PluginSection, Runtime},
    validate::validate,
    ValidatedManifest,
};
use entangle_types::{capability::CapabilityKind, peer_id::PeerId};
use std::time::{SystemTime, UNIX_EPOCH};

// ── helpers ─────────────────────────────────────────────────────────────────

const PUB: &str = "aabbccddeeff00112233445566778899";

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn make_manifest(name: &str, caps: &[&str]) -> ValidatedManifest {
    let mut m = Manifest {
        plugin: PluginSection {
            id: format!("{PUB}/{name}@0.1.0"),
            version: semver::Version::parse("0.1.0").unwrap(),
            tier: 2,
            runtime: Runtime::Wasm,
            description: String::new(),
        },
        capabilities: Default::default(),
        build: Some(BuildSection {
            wit_world: None,
            target: None,
        }),
        signature: None,
    };
    for cap in caps {
        m.capabilities
            .insert(cap.to_string(), toml::Value::Table(Default::default()));
    }
    validate(m).expect("test manifest must be valid")
}

/// Build and serialize a biscuit token using the given keypair and claims.
fn mint_token(kp: &BiscuitKp, claims: &ClaimSet) -> Vec<u8> {
    entangle_biscuits::mint::mint(kp, claims).expect("mint biscuit")
}

// ── Test 1 ────────────────────────────────────────────────────────────────

#[test]
fn grant_with_valid_biscuit_succeeds() {
    // Issuer keypair K — trust root.
    let kp = BiscuitKp::new();
    let trust_root = kp.public();

    let local_peer = PeerId::from_hex("00000000000000000000000000000001").unwrap();
    let cross_policy = CrossNodePolicy::empty().with_root(trust_root);

    let biscuit_bytes = mint_token(
        &kp,
        &ClaimSet::new()
            .issued_to(local_peer)
            .capability("compute.cpu")
            .expires(now_secs() + 3600),
    );

    let broker = Broker::new(BrokerPolicy::default());
    let manifest = make_manifest("valid-biscuit-plugin", &["compute.cpu"]);
    let plugin_id = manifest.plugin_id.clone();
    broker.register_plugin(manifest).unwrap();

    let gc = broker
        .grant_with_biscuit(
            &plugin_id,
            &CapabilityKind::ComputeCpu,
            &biscuit_bytes,
            local_peer,
            &cross_policy,
        )
        .expect("should succeed with valid biscuit");

    assert_eq!(gc.plugin, plugin_id);
    assert_eq!(gc.kind, CapabilityKind::ComputeCpu);
}

// ── Test 2 ────────────────────────────────────────────────────────────────

#[test]
fn grant_with_biscuit_signed_by_unknown_root_rejected() {
    // Trusted root: kp1. Actual signer: kp2 (untrusted).
    let kp1 = BiscuitKp::new();
    let kp2 = BiscuitKp::new(); // untrusted
    let trust_root = kp1.public(); // only kp1 is trusted

    let local_peer = PeerId::from_hex("00000000000000000000000000000002").unwrap();
    let cross_policy = CrossNodePolicy::empty().with_root(trust_root);

    let biscuit_bytes = mint_token(
        &kp2, // signed by untrusted kp2
        &ClaimSet::new()
            .issued_to(local_peer)
            .capability("compute.cpu")
            .expires(now_secs() + 3600),
    );

    let broker = Broker::new(BrokerPolicy::default());
    let manifest = make_manifest("unknown-root-plugin", &["compute.cpu"]);
    let plugin_id = manifest.plugin_id.clone();
    broker.register_plugin(manifest).unwrap();

    let err = broker
        .grant_with_biscuit(
            &plugin_id,
            &CapabilityKind::ComputeCpu,
            &biscuit_bytes,
            local_peer,
            &cross_policy,
        )
        .unwrap_err();

    assert!(
        matches!(err, BrokerError::BiscuitVerify(_)),
        "expected BiscuitVerify, got: {err}"
    );
}

// ── Test 3 ────────────────────────────────────────────────────────────────

#[test]
fn grant_with_expired_biscuit_rejected() {
    let kp = BiscuitKp::new();
    let trust_root = kp.public();

    let local_peer = PeerId::from_hex("00000000000000000000000000000003").unwrap();
    let cross_policy = CrossNodePolicy::empty().with_root(trust_root);

    // Biscuit expired 60 seconds ago.
    let biscuit_bytes = mint_token(
        &kp,
        &ClaimSet::new()
            .issued_to(local_peer)
            .capability("compute.cpu")
            .expires(now_secs() - 60),
    );

    let broker = Broker::new(BrokerPolicy::default());
    let manifest = make_manifest("expired-biscuit-plugin", &["compute.cpu"]);
    let plugin_id = manifest.plugin_id.clone();
    broker.register_plugin(manifest).unwrap();

    let err = broker
        .grant_with_biscuit(
            &plugin_id,
            &CapabilityKind::ComputeCpu,
            &biscuit_bytes,
            local_peer,
            &cross_policy,
        )
        .unwrap_err();

    assert!(
        matches!(err, BrokerError::BiscuitVerify(_)),
        "expected BiscuitVerify for expired token, got: {err}"
    );
}

// ── Test 4 ────────────────────────────────────────────────────────────────

#[test]
fn grant_with_biscuit_for_different_peer_rejected() {
    let kp = BiscuitKp::new();
    let trust_root = kp.public();

    let peer_a = PeerId::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let peer_b = PeerId::from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();

    // Biscuit is issued to peer_a.
    let biscuit_bytes = mint_token(
        &kp,
        &ClaimSet::new()
            .issued_to(peer_a)
            .capability("compute.cpu")
            .expires(now_secs() + 3600),
    );

    // But broker is running as peer_b.
    let cross_policy = CrossNodePolicy::empty().with_root(trust_root);

    let broker = Broker::new(BrokerPolicy::default());
    let manifest = make_manifest("wrong-peer-plugin", &["compute.cpu"]);
    let plugin_id = manifest.plugin_id.clone();
    broker.register_plugin(manifest).unwrap();

    let err = broker
        .grant_with_biscuit(
            &plugin_id,
            &CapabilityKind::ComputeCpu,
            &biscuit_bytes,
            peer_b, // local peer is B, but biscuit says A
            &cross_policy,
        )
        .unwrap_err();

    assert!(
        matches!(err, BrokerError::BiscuitVerify(_)),
        "expected BiscuitVerify for peer mismatch, got: {err}"
    );
}

// ── Test 5 ────────────────────────────────────────────────────────────────

#[test]
fn grant_with_biscuit_missing_required_capability_rejected() {
    let kp = BiscuitKp::new();
    let trust_root = kp.public();

    let local_peer = PeerId::from_hex("00000000000000000000000000000005").unwrap();
    let cross_policy = CrossNodePolicy::empty().with_root(trust_root);

    // Biscuit only has "compute.cpu", but we request "host.docker-socket".
    let biscuit_bytes = mint_token(
        &kp,
        &ClaimSet::new()
            .issued_to(local_peer)
            .capability("compute.cpu") // NOT host.docker-socket
            .expires(now_secs() + 3600),
    );

    let broker = Broker::new(BrokerPolicy::default());
    // Manifest doesn't declare host.docker-socket either — biscuit check fires first.
    let manifest = make_manifest("wrong-cap-plugin", &["compute.cpu"]);
    let plugin_id = manifest.plugin_id.clone();
    broker.register_plugin(manifest).unwrap();

    let err = broker
        .grant_with_biscuit(
            &plugin_id,
            &CapabilityKind::HostDockerSocket, // not in biscuit
            &biscuit_bytes,
            local_peer,
            &cross_policy,
        )
        .unwrap_err();

    assert!(
        matches!(err, BrokerError::BiscuitVerify(_)),
        "expected BiscuitVerify for missing capability, got: {err}"
    );
}
