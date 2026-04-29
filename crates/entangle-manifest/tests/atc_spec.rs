//! §16 Acceptance-Test Contract — manifest + tier group.
//!
//! Each test is named after its ATC ID so the iter-19 matrix runner can grep
//! them.  The IDs are taken verbatim from §16.1 of
//! `docs/superpowers/specs/2026-04-29-entanglement-architecture-v6.md`.
//!
//! ATC-MAN-3 and ATC-MAN-4 cannot be exercised here:
//!   • ATC-MAN-3 requires entangle-host (runtime instantiation / ELF sniffing)
//!   • ATC-MAN-4 requires entangle-bin (install command + broker config)

use entangle_manifest::{
    schema::{BuildSection, Manifest, PluginSection, Runtime},
    validate::{validate, ValidationError},
};
use entangle_types::tier::Tier;

// ── Publisher hex string used across helpers ─────────────────────────────────

const PUB: &str = "aabbccddeeff00112233445566778899";

// ── Shared helper ────────────────────────────────────────────────────────────

fn minimal_manifest(name: &str, tier: u8, runtime: Runtime) -> Manifest {
    Manifest {
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
    }
}

// ── ATC-MAN-1 ────────────────────────────────────────────────────────────────

/// §16 ATC-MAN-1 — under-declared tier is rejected with TierBelowCapability.
///
/// GIVEN  a manifest with `tier = 1` and a capability whose `min_tier = 5`
///        (`host.docker-socket` requires `Native`, i.e. tier 5)
/// WHEN   `validate(manifest)` is invoked
/// THEN   it returns `Err(ValidationError::TierBelowCapability { declared: Pure, implied: Native, … })`
#[test]
fn atc_man_1_tier_under_declared_rejected() {
    // GIVEN
    let mut m = minimal_manifest("too-low", 1, Runtime::Wasm);
    m.capabilities.insert(
        "host.docker-socket".into(),
        toml::Value::Table(Default::default()),
    );

    // WHEN
    let result = validate(m);

    // THEN
    let err = result.expect_err("under-declared tier must fail validation");
    match &err {
        ValidationError::TierBelowCapability {
            declared,
            implied,
            capability,
        } => {
            assert_eq!(*declared, Tier::Pure, "declared should be Pure(1)");
            assert_eq!(*implied, Tier::Native, "implied should be Native(5)");
            assert_eq!(capability, "host.docker-socket");
        }
        other => panic!("expected TierBelowCapability, got: {other}"),
    }
}

// ── ATC-MAN-2 ────────────────────────────────────────────────────────────────

/// §16 ATC-MAN-2 — over-declared tier is allowed; effective_tier equals declared.
///
/// GIVEN  a manifest with `tier = 5` but only tier-1 capabilities declared
///        (`compute.cpu` requires `Sandboxed`, i.e. tier 2, well below 5)
/// WHEN   `validate(manifest)` is invoked
/// THEN   it returns `Ok(_)` — over-declaration is legal; tier acts as a ceiling
///        AND `effective_tier == Native (5)` (clamped to declared, not implied)
#[test]
fn atc_man_2_tier_over_declared_ok() {
    // GIVEN — tier 5 (Native) with only compute.cpu (min_tier = Sandboxed/2)
    let mut m = minimal_manifest("over-declared", 5, Runtime::Native);
    m.capabilities
        .insert("compute.cpu".into(), toml::Value::Table(Default::default()));

    // WHEN
    let result = validate(m);

    // THEN
    let vm = result.expect("over-declared tier must succeed");
    assert_eq!(
        vm.effective_tier,
        Tier::Native,
        "effective_tier should equal the declared tier (5 = Native)"
    );
    assert_eq!(
        vm.declared_tier,
        Tier::Native,
        "declared_tier must be Native(5)"
    );
    // implied_tier is below declared — that is the over-declaration scenario
    assert!(
        vm.implied_tier < vm.declared_tier,
        "implied_tier ({:?}) must be < declared_tier ({:?}) in over-declaration",
        vm.implied_tier,
        vm.declared_tier
    );
}

// ── ATC-MAN-3 (out-of-scope stub) ────────────────────────────────────────────

// ATC-MAN-3: GIVEN runtime.kind = "wasm-component" AND the binary is actually ELF
//            WHEN  entangle-host instantiates the plugin
//            THEN  Err(Error::RuntimeKindMismatch { declared, observed })
//
// This proposition exercises entangle-host's instantiation path (ELF sniffing),
// not the manifest parser.  The test lives in:
//   crates/entangle-host/tests/runtime_kind.rs::lie_at_instantiation_rejected
//
// It is out of scope for this crate and will be covered in iter 15.

// ── ATC-MAN-4 (out-of-scope stub) ────────────────────────────────────────────

// ATC-MAN-4: GIVEN tier = 3 AND config [security] max_tier_allowed = 2
//            WHEN  `entangle install <manifest>` runs
//            THEN  Err(Error::TierExceeded { plugin_tier: 3, ceiling: 2 })
//            AND   no plugin state is mutated
//
// This proposition exercises the broker/install command (entangle-bin) and
// requires a runtime config surface that doesn't exist in this crate.
// The test lives in:
//   crates/entangle-bin/tests/install_max_tier.rs::install_rejects_above_ceiling
//
// It is out of scope for this crate and will be covered in iter 17.
