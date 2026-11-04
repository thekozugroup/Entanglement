//! §16 Acceptance-Test Contracts — types-level phase (Phase 1 /).
//!
//! These tests verify what can be asserted at the type level today:
//! correct field defaults, serde round-trips, and invariant assertions
//! on types. They do NOT enforce scheduling, Wasm instantiation, or
//! reputation tracking — those are Phase 3+ (entangle-plugin-scheduler).
//!
//! ATC IDs whose full contracts require the scheduler are implemented in the
//! scheduler's own tests (e.g. `crates/entangle-scheduler/tests/stream_atc.rs`
//! for ATC-INT-4/-6 and ATC-STR-1/-2/-3); the packaging, release and
//! governance ones (ATC-PKG/REL/BUS) are implemented where listed at the
//! bottom of this file.

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
// SemanticEquivalent threshold carries any f64
// ---------------------------------------------------------------------------

/// The type permits threshold values outside [0.0, 1.0]; validation is the
/// scheduler's responsibility, not the type's. (Formerly filed under
/// ATC-INT-4, which is the streaming submit-time check:
/// `crates/entangle-scheduler/tests/stream_atc.rs`.)
#[test]
fn semantic_equivalent_threshold_not_clamped_at_type_level() {
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
// ChannelSpec defaults: 1 MiB chunk, 256 MiB total, 30 min credit timeout
// ---------------------------------------------------------------------------

/// ChannelSpec default max_chunk_bytes = 1 MiB, max_total_bytes = 256 MiB
/// and credit-exhaustion timeout = 30 minutes per spec §7.1.
///
/// Runtime enforcement (stall, TotalBytesExceeded) is ATC-STR-1 / ATC-INT-6
/// in `crates/entangle-scheduler/tests/stream_atc.rs`.
#[test]
fn channel_spec_defaults_match_spec() {
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
    assert_eq!(ch.credit_exhaustion_timeout_ms, 30 * 60 * 1_000);
}

// ---------------------------------------------------------------------------
// PartialResultPolicy serializes as kebab-case
// ---------------------------------------------------------------------------

/// PartialResultPolicy variants serialize as kebab-case strings per serde
/// attribute.
#[test]
fn partial_result_policy_kebab_case_serde() {
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
// Operational ATC IDs live next to the code they check
// ---------------------------------------------------------------------------
//
// ATC-PKG-1..4   crates/entangle-cli/tests/reproducible.rs
// ATC-REL-1, -2  crates/entangle-cli/tests/release.rs,
//                crates/entangle-signing/tests/shamir.rs
// ATC-BUS-1, -2  tools/xtask/tests/governance.rs
// ATC-MIR-1, -2  crates/entangle-oci/tests
