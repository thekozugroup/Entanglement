//! §16 Acceptance-Test Contracts — types-level phase (Phase 1 /).
//!
//! These tests verify what can be asserted at the type level today:
//! correct field defaults, serde round-trips, and invariant assertions
//! on types. They do NOT enforce scheduling, Wasm instantiation, or
//! reputation tracking — those are Phase 3+ (entangle-plugin-scheduler).
//!
//! ATC IDs whose full contracts require the scheduler are marked
//! `#[ignore]` with a pointer to the spec section and future crate.

use entangle_types::{
    errors::EntangleError,
    peer_id::PeerId,
    plugin_id::PluginId,
    task::{ChannelSpec, IntegrityPolicy, MetricRef, OneShotTask, PartialResultPolicy},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_plugin() -> PluginId {
    "aabbccddeeff00112233445566778899/test-plugin@1.0.0"
        .parse()
        .expect("valid plugin id")
}

/// A `SemanticEquivalent` policy with an arbitrary (unchecked) threshold.
fn semantic_equivalent(threshold: f64) -> IntegrityPolicy {
    IntegrityPolicy::SemanticEquivalent {
        replicas: 3,
        quorum: 2,
        metric: MetricRef {
            plugin: test_plugin(),
            publisher_key: [1u8; 32],
            artifact_blake3: [2u8; 32],
        },
        threshold,
    }
}

// ---------------------------------------------------------------------------
// OneShotTask default max_output_bytes is 16 MiB (§7.1 / INV-INT-2)
// ---------------------------------------------------------------------------

/// §7.1 / INV-INT-2 — OneShotTask default max_output_bytes is 16 MiB.
///
/// The spec (§7.1 size-limit table) mandates `max_output_bytes` defaults to
/// 16 MiB = 16 * 1024 * 1024 bytes. This test verifies the constant and
/// the `with_defaults` constructor honour that value.
#[test]
fn max_output_default_16mib() {
    const MIB_16: u64 = 16 * 1024 * 1024;

    // Constant on the type
    assert_eq!(
        OneShotTask::DEFAULT_MAX_OUTPUT_BYTES,
        MIB_16,
        "DEFAULT_MAX_OUTPUT_BYTES must be 16 MiB per §7.1"
    );

    // Constructor honours the default
    let task = OneShotTask::with_defaults(test_plugin(), vec![1, 2, 3]);
    assert_eq!(
        task.max_output_bytes, MIB_16,
        "with_defaults must set max_output_bytes to 16 MiB"
    );
    // max_input_bytes also defaults to 16 MiB
    assert_eq!(task.max_input_bytes, MIB_16);
}

// ---------------------------------------------------------------------------
// max_output_bytes — explicit field override is preserved
// ---------------------------------------------------------------------------

/// GIVEN OneShotTask with max_output_bytes = 1024, WHEN constructed, THEN the
/// field is carried on the type unchanged.
///
/// Enforcement (Err(OutputSizeExceeded) before metric instantiation) is
/// ATC-INT-5: `crates/entangle-scheduler/tests/integrity_atc.rs`.
#[test]
fn max_output_bytes_field_carried() {
    let mut task = OneShotTask::with_defaults(test_plugin(), vec![]);
    task.max_output_bytes = 1024;
    assert_eq!(task.max_output_bytes, 1024);
}

// ---------------------------------------------------------------------------
// IntegrityPolicy serde round-trips
// ---------------------------------------------------------------------------

/// GIVEN IntegrityPolicy::TrustedExecutor with an allowlist, WHEN serialized
/// to JSON and back, THEN the value is identical.
///
/// INV-INT-1 (policy immutability) is enforced by the scheduler via the
/// `policy_hash` envelope; ATC-INT-3 is
/// `crates/entangle-scheduler/tests/integrity_atc.rs`.
/// Here we verify the type satisfies `Serialize + Deserialize + PartialEq` and
/// that round-trip produces the same value.
#[test]
fn integrity_policy_trusted_executor_json_round_trip() {
    let allowlist: Vec<PeerId> = vec![];
    let policy = IntegrityPolicy::TrustedExecutor { allowlist };
    let json = serde_json::to_string(&policy).expect("serialize");
    let back: IntegrityPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(policy, back);
}

/// TOML round-trip for IntegrityPolicy::None.
///
/// TOML serialization is used in work-unit envelopes; verifies the type is
/// TOML-compatible without scheduler machinery.
#[test]
fn integrity_policy_none_toml_round_trip() {
    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Wrapper {
        policy: IntegrityPolicy,
    }
    let w = Wrapper {
        policy: IntegrityPolicy::None,
    };
    let toml_str = toml::to_string(&w).expect("serialize to toml");
    let back: Wrapper = toml::from_str(&toml_str).expect("deserialize from toml");
    assert_eq!(w, back);
}

// ---------------------------------------------------------------------------
// ATC-INT-4 (types-tier) — SemanticEquivalent threshold carries any f32
// ---------------------------------------------------------------------------

/// §16 ATC-INT-4 (types-tier) — The type permits threshold values outside
/// [0.0, 1.0]; validation is the scheduler's responsibility, not the type's.
#[test]
fn atc_int_4_semantic_equivalent_threshold_not_clamped_at_type_level() {
    let over = semantic_equivalent(1.5);
    let under = semantic_equivalent(-0.1);
    // The type accepts these values — enforcement is the scheduler's job.
    match over {
        IntegrityPolicy::SemanticEquivalent { threshold, .. } => {
            assert!(threshold > 1.0, "type must carry out-of-range threshold")
        }
        _ => panic!("wrong variant"),
    }
    match under {
        IntegrityPolicy::SemanticEquivalent { threshold, .. } => {
            assert!(threshold < 0.0, "type must carry negative threshold")
        }
        _ => panic!("wrong variant"),
    }
}

// ---------------------------------------------------------------------------
// ATC-STR-1 (types-tier) — ChannelSpec defaults: 1 MiB chunk, 256 MiB total
// ---------------------------------------------------------------------------

/// §16 ATC-STR-1 (types-tier) — ChannelSpec default max_chunk_bytes = 1 MiB
/// and max_total_bytes = 256 MiB per spec §7.1.
///
/// Runtime enforcement (stall, TotalBytesExceeded) is ATC-STR-1 / ATC-INT-6
/// proper in entangle-plugin-scheduler (Phase 3).
#[test]
fn atc_str_1_channel_spec_defaults_match_spec() {
    let ch = ChannelSpec::default();
    assert_eq!(
        ch.max_chunk_bytes,
        1024 * 1024,
        "max_chunk_bytes must default to 1 MiB per §7.1"
    );
    assert_eq!(
        ch.max_total_bytes,
        256 * 1024 * 1024,
        "max_total_bytes must default to 256 MiB per §7.1"
    );
    assert_eq!(ch.credit_window, 16);
    assert_eq!(ch.heartbeat_ms, 5_000);
}

// ---------------------------------------------------------------------------
// ATC-STR-2 (types-tier) — PartialResultPolicy serializes as kebab-case
// ---------------------------------------------------------------------------

/// §16 ATC-STR-2 (types-tier) — PartialResultPolicy variants serialize as
/// kebab-case strings per serde attribute.
#[test]
fn atc_str_2_partial_result_policy_kebab_case_serde() {
    let cases = [
        (PartialResultPolicy::Discard, "\"discard\""),
        (PartialResultPolicy::Keep, "\"keep\""),
        (PartialResultPolicy::KeepSigned, "\"keep-signed\""),
    ];
    for (variant, expected_json) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(
            json, expected_json,
            "PartialResultPolicy::{variant:?} must serialize as {expected_json}"
        );
        let back: PartialResultPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(variant, back);
    }
}

// ---------------------------------------------------------------------------
// ATC-OUT-1 — EntangleError::OutputSizeExceeded Display matches ENTANGLE-E0300
// ---------------------------------------------------------------------------

/// §16 ATC-OUT-1 — EntangleError::OutputSizeExceeded Display format contains
/// the ENTANGLE-E0300 error code and the declared/actual/peer values.
///
/// Spec §0 error table defines:
/// "ENTANGLE-E0300: output exceeds max_output_bytes (declared D, actual A) from peer P"
#[test]
fn atc_out_1_output_size_exceeded_display_format() {
    let err = EntangleError::OutputSizeExceeded {
        declared: 1024,
        actual: 2048,
        peer: "peer-abc".into(),
    };
    let msg = err.to_string();
    assert!(
        msg.contains("ENTANGLE-E0300"),
        "must contain error code; got: {msg}"
    );
    assert!(
        msg.contains("1024"),
        "must contain declared value; got: {msg}"
    );
    assert!(
        msg.contains("2048"),
        "must contain actual value; got: {msg}"
    );
    assert!(msg.contains("peer-abc"), "must contain peer; got: {msg}");
}

// ---------------------------------------------------------------------------
// Placeholder / deferred ATC IDs — require Phase 3+ runtime code
// ---------------------------------------------------------------------------

/// §16 ATC-INT-4 (scheduler-tier) — StreamingTask + Deterministic rejected at submit-time.
///
/// Requires InvalidIntegrityForStreaming error in entangle-plugin-scheduler.
/// Deferred to: crates/entangle-plugin-scheduler/tests/submit_validation.rs
/// Future iteration: Phase 3.
#[test]
#[ignore = "Phase 3: requires entangle-plugin-scheduler submit-time validation"]
fn atc_int_4_streaming_deterministic_rejected_at_submit() {
    unimplemented!("§16 ATC-INT-4 — see crates/entangle-plugin-scheduler Phase 3")
}

/// §16 ATC-INT-6 — StreamingTask total-byte cap enforced at runtime.
///
/// Requires scheduler stream tracking and Reason::TotalBytesExceeded teardown.
/// Deferred to: crates/entangle-plugin-scheduler/tests/stream_total_bytes.rs
/// Future iteration: Phase 3.
#[test]
#[ignore = "Phase 3: requires entangle-plugin-scheduler stream byte tracking"]
fn atc_int_6_streaming_total_bytes_cap_enforced() {
    unimplemented!("§16 ATC-INT-6 — see crates/entangle-plugin-scheduler Phase 3")
}

/// §16 ATC-STR-1 (scheduler-tier) — credit-exhaustion stall within timeout.
///
/// Deferred to: crates/entangle-plugin-scheduler/tests/stream_stall.rs
/// Future iteration: Phase 3.
#[test]
#[ignore = "Phase 3: requires entangle-plugin-scheduler credit/stall machinery"]
fn atc_str_1_credit_exhaustion_stalls_at_timeout() {
    unimplemented!("§16 ATC-STR-1 — see crates/entangle-plugin-scheduler Phase 3")
}

/// §16 ATC-STR-2 (scheduler-tier) — three missed heartbeat pings close channel.
///
/// Deferred to: crates/entangle-plugin-scheduler/tests/stream_heartbeat.rs
/// Future iteration: Phase 3.
#[test]
#[ignore = "Phase 3: requires entangle-plugin-scheduler heartbeat ping/pong machinery"]
fn atc_str_2_three_missed_pings_close_channel() {
    unimplemented!("§16 ATC-STR-2 — see crates/entangle-plugin-scheduler Phase 3")
}

/// §16 ATC-STR-3 — forged chunk signature rejected.
///
/// Deferred to: crates/entangle-plugin-scheduler/tests/stream_signing.rs
/// Future iteration: Phase 3.
#[test]
#[ignore = "Phase 3: requires entangle-plugin-scheduler chunk signing verification"]
fn atc_str_3_forged_chunk_rejected() {
    unimplemented!("§16 ATC-STR-3 — see crates/entangle-plugin-scheduler Phase 3")
}

/// §16 ATC-BUS-1, ATC-BUS-2 — bus / rotation governance invariants.
///
/// These are operational / process invariants verified by release CI workflow
/// and governance documentation, not unit tests.
/// Deferred to: release CI (ATC-BUS-1: INV-BUS-1 rotation freshness) and
/// governance docs. Future iteration: release pipeline Phase 5+.
#[test]
#[ignore = "Phase 5+: operational invariants verified in release CI / governance docs"]
fn atc_bus_rotation_governance_invariants() {
    unimplemented!("§16 ATC-BUS-1/2 — verified in release CI workflow, not unit tests")
}

/// §16 ATC-MIRROR-1, ATC-RELEASE-1 — mirror/release operational invariants.
///
/// These are release-process invariants (mirror consistency, release signing).
/// Verified in release CI; not unit-testable.
/// Future iteration: Phase 5+ release pipeline.
#[test]
#[ignore = "Phase 5+: release/mirror invariants verified in release CI, not unit tests"]
fn atc_mirror_release_operational_invariants() {
    unimplemented!("§16 ATC-MIRROR-1 / ATC-RELEASE-1 — see release CI workflow Phase 5+")
}
