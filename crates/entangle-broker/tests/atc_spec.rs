//! Acceptance-test contract for `entangle-broker` — §16 ATC IDs.
//!
//! Each test carries a doc-comment with a `§16 ATC-*` identifier so the
//! matrix runner (iter 19) can scrape them with:
//!
//! ```text
//! grep -rn "§16 ATC-" crates/entangle-broker/tests/
//! ```
//!
//! # Coverage
//!
//! | ATC ID          | Description                                              |
//! |-----------------|----------------------------------------------------------|
//! | ATC-CAP-1       | Declared capability → granted handle + audit event       |
//! | ATC-CAP-2       | Undeclared capability → CapabilityNotDeclared + denied   |
//! | ATC-CAP-3       | Released grant → new grant gets distinct id              |
//! | ATC-MAX-TIER-1  | max_tier_allowed < plugin tier → TierAboveCeiling        |
//! | ATC-MAX-TIER-2  | max_tier_allowed >= plugin tier → ok                     |
//! | ATC-AUDIT-1     | Every broker decision records an AuditEvent              |
//! | ATC-AUDIT-2     | Unregister → CapabilityReleased + PluginUnregistered     |

use entangle_broker::{
    audit::AuditEvent, broker::Broker, errors::BrokerError, policy::BrokerPolicy,
};
use entangle_manifest::{
    schema::{BuildSection, Manifest, PluginSection, Runtime},
    validate::validate,
};
use entangle_types::{capability::CapabilityKind, tier::Tier};

// ── Test helper ──────────────────────────────────────────────────────────────

/// Publisher hex used throughout these tests.
const PUB: &str = "aabbccddeeff00112233445566778899";

/// Build a `ValidatedManifest` directly from raw components, bypassing TOML
/// file I/O. Mirrors the pattern established in iter 7 unit tests.
fn make_manifest(
    name: &str,
    tier: u8,
    runtime: Runtime,
    caps: &[&str],
) -> entangle_manifest::validate::ValidatedManifest {
    let mut m = Manifest {
        plugin: PluginSection {
            id: format!("{PUB}/{name}@0.1.0"),
            version: semver::Version::parse("0.1.0").unwrap(),
            tier,
            runtime,
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

// ── ATC-CAP-1 ────────────────────────────────────────────────────────────────

/// §16 ATC-CAP-1 — GIVEN plugin manifest with declared capability X,
/// WHEN broker grants X, THEN a `GrantedCapability` handle is returned
/// and `AuditEvent::CapabilityGranted` is recorded in the audit log.
#[test]
fn atc_cap_1_grant_records_audit() {
    let broker = Broker::new(BrokerPolicy::default());
    let manifest = make_manifest("cap1-plugin", 2, Runtime::Wasm, &["compute.cpu"]);
    let plugin_id = manifest.plugin_id.clone();
    broker.register_plugin(manifest).unwrap();

    let gc = broker
        .grant(&plugin_id, &CapabilityKind::ComputeCpu)
        .expect("ATC-CAP-1: declared capability must be granted");

    // Returned handle must reference the correct plugin and capability kind.
    assert_eq!(gc.plugin, plugin_id, "ATC-CAP-1: handle.plugin mismatch");
    assert_eq!(
        gc.kind,
        CapabilityKind::ComputeCpu,
        "ATC-CAP-1: handle.kind mismatch"
    );
    assert!(gc.grant_id >= 1, "ATC-CAP-1: grant_id must be >= 1");

    // Audit log must contain a CapabilityGranted event.
    let events = broker.audit_log().snapshot();
    let granted = events.iter().any(|e| {
        matches!(
            e,
            AuditEvent::CapabilityGranted { capability, .. }
                if capability == "compute.cpu"
        )
    });
    assert!(granted, "ATC-CAP-1: expected AuditEvent::CapabilityGranted");
}

// ── ATC-CAP-2 ────────────────────────────────────────────────────────────────

/// §16 ATC-CAP-2 — GIVEN plugin manifest WITHOUT capability X,
/// WHEN broker is asked to grant X, THEN `BrokerError::CapabilityNotDeclared`
/// is returned and `AuditEvent::CapabilityDenied` is recorded.
#[test]
fn atc_cap_2_undeclared_capability_denied() {
    let broker = Broker::new(BrokerPolicy::default());
    // Plugin only declares compute.cpu — does NOT declare host.docker-socket.
    let manifest = make_manifest("cap2-plugin", 2, Runtime::Wasm, &["compute.cpu"]);
    let plugin_id = manifest.plugin_id.clone();
    broker.register_plugin(manifest).unwrap();

    let err = broker
        .grant(&plugin_id, &CapabilityKind::HostDockerSocket)
        .expect_err("ATC-CAP-2: undeclared capability must be denied");

    assert!(
        matches!(err, BrokerError::CapabilityNotDeclared { .. }),
        "ATC-CAP-2: expected BrokerError::CapabilityNotDeclared, got: {err}"
    );

    // Audit log must contain a CapabilityDenied event.
    let events = broker.audit_log().snapshot();
    let denied = events.iter().any(|e| {
        matches!(
            e,
            AuditEvent::CapabilityDenied { capability, .. }
                if capability == "host.docker-socket"
        )
    });
    assert!(denied, "ATC-CAP-2: expected AuditEvent::CapabilityDenied");
}

// ── ATC-CAP-3 ────────────────────────────────────────────────────────────────

/// §16 ATC-CAP-3 — GIVEN granted capability with grant_id G, WHEN released,
/// THEN `AuditEvent::CapabilityReleased` is recorded and a subsequent grant
/// of the same capability receives a new (distinct, higher) grant_id.
#[test]
fn atc_cap_3_release_then_regrant_new_id() {
    let broker = Broker::new(BrokerPolicy::default());
    let manifest = make_manifest("cap3-plugin", 2, Runtime::Wasm, &["compute.cpu"]);
    let plugin_id = manifest.plugin_id.clone();
    broker.register_plugin(manifest).unwrap();

    // First grant.
    let gc1 = broker
        .grant(&plugin_id, &CapabilityKind::ComputeCpu)
        .expect("ATC-CAP-3: first grant must succeed");
    let original_id = gc1.grant_id;

    // Release the grant.
    broker
        .release(&plugin_id, gc1.grant_id)
        .expect("ATC-CAP-3: release must succeed");

    // Audit log must contain a CapabilityReleased event for the original id.
    let events_after_release = broker.audit_log().snapshot();
    let released = events_after_release.iter().any(|e| {
        matches!(
            e,
            AuditEvent::CapabilityReleased { grant_id, .. }
                if *grant_id == original_id
        )
    });
    assert!(
        released,
        "ATC-CAP-3: expected AuditEvent::CapabilityReleased"
    );

    // Second grant must have a strictly higher grant_id (monotonic counter).
    let gc2 = broker
        .grant(&plugin_id, &CapabilityKind::ComputeCpu)
        .expect("ATC-CAP-3: second grant must succeed");
    assert!(
        gc2.grant_id > original_id,
        "ATC-CAP-3: new grant_id ({}) must be > released id ({})",
        gc2.grant_id,
        original_id
    );
}

// ── ATC-MAX-TIER-1 ───────────────────────────────────────────────────────────

/// §16 ATC-MAX-TIER-1 — GIVEN policy with `max_tier_allowed = Sandboxed`,
/// WHEN a plugin with `effective_tier = Native` attempts to register,
/// THEN `BrokerError::Policy(TierAboveCeiling)` is returned.
#[test]
fn atc_max_tier_1_native_blocked_by_sandboxed_ceiling() {
    let policy = BrokerPolicy {
        max_tier_allowed: Tier::Sandboxed,
        ..Default::default()
    };
    let broker = Broker::new(policy);
    // tier=5 + Runtime::Native → effective_tier = Native (tier 5).
    let manifest = make_manifest(
        "max-tier1-plugin",
        5,
        Runtime::Native,
        &["host.docker-socket"],
    );

    let err = broker
        .register_plugin(manifest)
        .expect_err("ATC-MAX-TIER-1: native plugin must be rejected by sandboxed ceiling");

    assert!(
        matches!(
            err,
            BrokerError::Policy(entangle_broker::policy::PolicyError::TierAboveCeiling { .. })
        ),
        "ATC-MAX-TIER-1: expected BrokerError::Policy(TierAboveCeiling), got: {err}"
    );
}

// ── ATC-MAX-TIER-2 ───────────────────────────────────────────────────────────

/// §16 ATC-MAX-TIER-2 — GIVEN policy with `max_tier_allowed = Native`,
/// WHEN a plugin with `effective_tier = Pure` (tier 1) registers,
/// THEN registration succeeds.
#[test]
fn atc_max_tier_2_pure_plugin_allowed_under_native_ceiling() {
    let policy = BrokerPolicy {
        max_tier_allowed: Tier::Native,
        ..Default::default()
    };
    let broker = Broker::new(policy);
    // tier=1, Wasm, no capabilities → effective_tier = Pure.
    let manifest = make_manifest("max-tier2-plugin", 1, Runtime::Wasm, &[]);

    broker
        .register_plugin(manifest)
        .expect("ATC-MAX-TIER-2: pure plugin must be accepted under native ceiling");
}

// ── ATC-AUDIT-1 ──────────────────────────────────────────────────────────────

/// §16 ATC-AUDIT-1 — GIVEN any broker decision, WHEN it occurs,
/// THEN at least one `AuditEvent` is appended to the audit log.
///
/// Covers register, grant, deny, and release in a single flow.
#[test]
fn atc_audit_1_every_decision_recorded() {
    let broker = Broker::new(BrokerPolicy::default());

    // Before any action: log is empty.
    assert_eq!(
        broker.audit_log().len(),
        0,
        "ATC-AUDIT-1: audit log must start empty"
    );

    // Register → should produce PluginRegistered.
    let manifest = make_manifest("audit1-plugin", 2, Runtime::Wasm, &["compute.cpu"]);
    let plugin_id = manifest.plugin_id.clone();
    broker.register_plugin(manifest).unwrap();
    assert!(
        !broker.audit_log().snapshot().is_empty(),
        "ATC-AUDIT-1: register must append an audit event"
    );

    let after_register = broker.audit_log().len();

    // Grant → should produce CapabilityGranted.
    let gc = broker
        .grant(&plugin_id, &CapabilityKind::ComputeCpu)
        .unwrap();
    assert!(
        broker.audit_log().len() > after_register,
        "ATC-AUDIT-1: grant must append an audit event"
    );

    let after_grant = broker.audit_log().len();

    // Deny → should produce CapabilityDenied.
    let _ = broker.grant(&plugin_id, &CapabilityKind::HostDockerSocket);
    assert!(
        broker.audit_log().len() > after_grant,
        "ATC-AUDIT-1: deny must append an audit event"
    );

    let after_deny = broker.audit_log().len();

    // Release → should produce CapabilityReleased.
    broker.release(&plugin_id, gc.grant_id).unwrap();
    assert!(
        broker.audit_log().len() > after_deny,
        "ATC-AUDIT-1: release must append an audit event"
    );
}

// ── ATC-AUDIT-2 ──────────────────────────────────────────────────────────────

/// §16 ATC-AUDIT-2 — GIVEN a registered plugin with outstanding capability
/// grants, WHEN the plugin is unregistered, THEN the audit log contains both
/// `AuditEvent::CapabilityReleased` (for each outstanding grant) and
/// `AuditEvent::PluginUnregistered`.
#[test]
fn atc_audit_2_unregister_emits_released_and_unregistered() {
    let broker = Broker::new(BrokerPolicy::default());
    let manifest = make_manifest("audit2-plugin", 2, Runtime::Wasm, &["compute.cpu"]);
    let plugin_id = manifest.plugin_id.clone();
    broker.register_plugin(manifest).unwrap();

    // Obtain two outstanding grants.
    let gc1 = broker
        .grant(&plugin_id, &CapabilityKind::ComputeCpu)
        .unwrap();
    let gc2 = broker
        .grant(&plugin_id, &CapabilityKind::ComputeCpu)
        .unwrap();

    // Unregister — broker must auto-release all outstanding grants.
    broker
        .unregister_plugin(&plugin_id)
        .expect("ATC-AUDIT-2: unregister must succeed");

    let events = broker.audit_log().snapshot();

    // CapabilityReleased must appear for both grant ids.
    for expected_gid in [gc1.grant_id, gc2.grant_id] {
        let released = events.iter().any(|e| {
            matches!(
                e,
                AuditEvent::CapabilityReleased { grant_id, .. }
                    if *grant_id == expected_gid
            )
        });
        assert!(
            released,
            "ATC-AUDIT-2: expected CapabilityReleased for grant_id={expected_gid}"
        );
    }

    // PluginUnregistered must appear for the plugin.
    let unregistered = events.iter().any(
        |e| matches!(e, AuditEvent::PluginUnregistered { plugin, .. } if plugin == &plugin_id),
    );
    assert!(
        unregistered,
        "ATC-AUDIT-2: expected AuditEvent::PluginUnregistered for {plugin_id}"
    );
}
