//! §16 Acceptance-Test Contract — manifest + tier group.
//!
//! Each test is named after its ATC ID so the matrix runner can grep
//! them. The IDs are taken verbatim from §16.1 of
//! `docs/superpowers/specs/2026-04-29-entanglement-architecture-v6.md`.
//!
//! ATC-MAN-3 and ATC-MAN-4 cannot be exercised here:
//! • ATC-MAN-3 requires entangle-host (runtime instantiation / ELF sniffing)
//! • ATC-MAN-4 requires entangle-bin (install command + broker config)

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
/// GIVEN a manifest with `tier = 1` and a capability whose `min_tier = 5`
/// (`host.docker-socket` requires `Native`, i.e. tier 5)
/// WHEN `validate(manifest)` is invoked
/// THEN it returns `Err(ValidationError::TierBelowCapability { declared: Pure, implied: Native, … })`
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

/// The acceptance example specifically requires a tier-3 capability.
#[test]
fn atc_man_1_tier_one_rejects_tier_three_capability() {
    let mut manifest = minimal_manifest("network-under-declared", 1, Runtime::Wasm);
    manifest
        .capabilities
        .insert("net.lan".into(), toml::Value::Table(Default::default()));
    assert!(matches!(
        validate(manifest),
        Err(ValidationError::TierBelowCapability {
            declared: Tier::Pure,
            implied: Tier::Networked,
            capability,
        }) if capability == "net.lan"
    ));
}

// ── ATC-MAN-2 ────────────────────────────────────────────────────────────────

/// §16 ATC-MAN-2 — over-declared tier is allowed; effective_tier equals declared.
///
/// GIVEN a manifest with `tier = 5` but only tier-1 capabilities declared
/// (`compute.cpu` requires `Sandboxed`, i.e. tier 2, well below 5)
/// WHEN `validate(manifest)` is invoked
/// THEN it returns `Ok(_)` — over-declaration is legal; tier acts as a ceiling
/// AND `effective_tier == Native (5)` (clamped to declared, not implied)
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

/// A tier-5 manifest may declare only a tier-1 private storage capability.
#[test]
fn atc_man_2_tier_five_accepts_only_tier_one_capabilities() {
    let mut manifest = minimal_manifest("pure-cap-native-ceiling", 5, Runtime::Native);
    manifest.capabilities.insert(
        "storage.local".into(),
        toml::Value::Table(Default::default()),
    );
    let validated = validate(manifest).expect("over-declaration is allowed");
    assert_eq!(validated.implied_tier, Tier::Pure);
    assert_eq!(validated.declared_tier, Tier::Native);
    assert_eq!(validated.effective_tier, Tier::Native);
}

// ── ATC-MAN-3 (out-of-scope stub) ────────────────────────────────────────────

// ATC-MAN-3: GIVEN runtime.kind = "wasm-component" AND the binary is actually ELF
// WHEN entangle-host instantiates the plugin
// THEN Err(Error::RuntimeKindMismatch { declared, observed })
//
// This proposition exercises entangle-host's instantiation path (ELF sniffing),
// not the manifest parser. The test lives in:
// crates/entangle-host/tests/runtime_kind.rs::lie_at_instantiation_rejected
//
// It is out of scope for this crate and will be covered in.

// ── ATC-MAN-4 (out-of-scope stub) ────────────────────────────────────────────

// ATC-MAN-4: GIVEN tier = 3 AND config [security] max_tier_allowed = 2
// WHEN `entangle install <manifest>` runs
// THEN Err(Error::TierExceeded { plugin_tier: 3, ceiling: 2 })
// AND no plugin state is mutated
//
// This proposition exercises the broker/install command (entangle-bin) and
// requires a runtime config surface that doesn't exist in this crate.
// The test lives in:
// crates/entangle-bin/tests/install_max_tier.rs::install_rejects_above_ceiling
//
// It is out of scope for this crate and will be covered in.

#[test]
fn canonical_under_declaration_names_specific_required_tier() {
    let mut manifest = minimal_manifest("underdeclared", 1, Runtime::Wasm);
    manifest
        .capabilities
        .insert("net.lan".into(), toml::Value::Table(Default::default()));
    assert!(matches!(entangle_manifest::validate(manifest),
        Err(entangle_manifest::Error::TierUnderDeclared { cap, min_tier: Tier::Networked, declared: Tier::Pure }) if cap == "net.lan"));
}

#[test]
fn separate_runtime_kind_is_recognized_and_conflicting_declarations_are_rejected() {
    let text = format!("[plugin]\nid='{PUB}/test@1.0.0'\nversion='1.0.0'\ntier=1\n[runtime]\nkind='wasm-component'\n");
    let parsed: Manifest = toml::from_str(&text).unwrap();
    assert_eq!(
        entangle_manifest::validate(parsed).unwrap().runtime,
        Runtime::Wasm
    );
    let conflict = text.replace("tier=1", "tier=1\nruntime='native'");
    assert!(toml::from_str::<Manifest>(&conflict)
        .unwrap_err()
        .to_string()
        .contains("conflicting"));
}
