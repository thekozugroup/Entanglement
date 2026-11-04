//! Spec §4.3 / §12 M3: "tier_required = max(cap.min_tier)" and "a property
//! test enforces monotonicity", over 10 000 random manifests.
//!
//! The oracle below restates the §4.2 capability/tier table independently of
//! `CapabilityKind::min_tier`, so a drifted table entry fails here instead of
//! being echoed back by the code under test.

use entangle_manifest::{
    schema::{Manifest, PluginSection, Runtime},
    validate::{validate, ValidationError},
};
use entangle_types::tier::Tier;
use proptest::prelude::*;

const PUB: &str = "aabbccddeeff00112233445566778899";

/// A capability as a manifest would declare it, plus its §4.2 minimum tier.
#[derive(Debug, Clone)]
struct Cap {
    key: String,
    args: toml::Table,
    min_tier: u8,
}

fn table(pairs: &[(&str, toml::Value)]) -> toml::Table {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect()
}

fn s(v: &str) -> toml::Value {
    toml::Value::String(v.to_owned())
}

fn hosts(list: &[&str]) -> toml::Value {
    toml::Value::Array(list.iter().map(|h| s(h)).collect())
}

fn cap(key: &str, args: toml::Table, min_tier: u8) -> Cap {
    Cap {
        key: key.to_owned(),
        args,
        min_tier,
    }
}

fn arb_cap() -> impl Strategy<Value = Cap> {
    prop_oneof![
        Just(cap("compute.cpu", table(&[]), 2)),
        Just(cap("compute.gpu", table(&[]), 3)),
        Just(cap("compute.npu", table(&[]), 3)),
        prop_oneof![Just("ro"), Just("rw")].prop_flat_map(|mode| prop_oneof![
            Just(cap(
                "storage.local",
                table(&[("scope", s("plugin")), ("mode", s(mode))]),
                1
            )),
            Just(cap(
                "storage.local",
                table(&[("scope", s("shared")), ("mode", s(mode))]),
                2
            )),
        ]),
        (
            "[a-z0-9][a-z0-9_-]{0,12}",
            prop_oneof![Just("ro"), Just("rw"), Just("rw-scoped")]
        )
            .prop_map(|(name, mode)| cap(
                &format!("storage.share.{name}"),
                table(&[("mode", s(mode))]),
                4
            )),
        Just(cap("net.lan", table(&[]), 3)),
        // Pinned hosts: tier 3. Any wildcard (or no allowlist): tier 4.
        prop::collection::vec("[a-z]{1,8}\\.example\\.com(:443)?", 1..4).prop_map(|h| {
            let refs: Vec<&str> = h.iter().map(String::as_str).collect();
            cap("net.wan", table(&[("hosts", hosts(&refs))]), 3)
        }),
        Just(cap("net.wan", table(&[("hosts", hosts(&["*"]))]), 4)),
        Just(cap(
            "net.wan",
            table(&[("hosts", hosts(&["api.example.com:443", "*.example.org"]))]),
            4
        )),
        Just(cap("net.wan", table(&[]), 4)),
        Just(cap("mesh.peer", table(&[]), 4)),
        Just(cap("agent.invoke", table(&[]), 2)),
        Just(cap("host.docker-socket", table(&[]), 5)),
        "[a-z]{1,10}".prop_map(|n| cap(&format!("custom.{n}"), table(&[]), 1)),
    ]
}

/// Distinct keys only: a manifest declares each key at most once.
fn dedup(caps: Vec<Cap>) -> Vec<Cap> {
    let mut seen = std::collections::BTreeSet::new();
    caps.into_iter()
        .filter(|c| seen.insert(c.key.clone()))
        .collect()
}

fn arb_caps() -> impl Strategy<Value = Vec<Cap>> {
    prop::collection::vec(arb_cap(), 0..8).prop_map(dedup)
}

fn tier_of(n: u8) -> Tier {
    Tier::try_from(n).expect("1..=5")
}

fn expected_implied(caps: &[Cap]) -> u8 {
    caps.iter().map(|c| c.min_tier).max().unwrap_or(1)
}

/// Build a manifest; the runtime is chosen so that only the tier rule can
/// reject it (wasm for effective tier <= 3, native above).
fn manifest(declared: u8, caps: &[Cap]) -> Manifest {
    let effective = declared.max(expected_implied(caps));
    Manifest {
        plugin: PluginSection {
            id: format!("{PUB}/prop@0.1.0"),
            version: semver::Version::parse("0.1.0").expect("valid"),
            tier: declared,
            runtime: if effective >= 4 {
                Runtime::Native
            } else {
                Runtime::Wasm
            },
            description: String::new(),
        },
        capabilities: caps
            .iter()
            .map(|c| (c.key.clone(), toml::Value::Table(c.args.clone())))
            .collect(),
        build: None,
        signature: None,
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 10_000,
        // The failure-persistence file would be written next to the sources.
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    /// implied tier == max(min_tier) of the declared capabilities (Pure when
    /// none), and validation of an under-declared tier fails exactly when
    /// declared < implied.
    #[test]
    fn implied_tier_is_the_max_and_under_declaration_fails_exactly(
        caps in arb_caps(),
        declared in 1u8..=5,
    ) {
        let implied = expected_implied(&caps);
        let result = validate(manifest(declared, &caps));
        if declared < implied {
            match result {
                Err(ValidationError::TierBelowCapability { declared: d, implied: i, .. }) => {
                    prop_assert_eq!(d, tier_of(declared));
                    prop_assert_eq!(i, tier_of(implied));
                }
                other => prop_assert!(false, "expected TierBelowCapability, got {:?}", other.map(|v| v.implied_tier)),
            }
        } else {
            let v = result.map_err(|e| TestCaseError::fail(format!("rejected: {e}")))?;
            prop_assert_eq!(v.implied_tier, tier_of(implied));
            prop_assert_eq!(v.declared_tier, tier_of(declared));
            prop_assert_eq!(v.effective_tier, tier_of(declared.max(implied)));
        }
    }

    /// Monotonicity: adding a capability never lowers the implied tier, and
    /// the new implied tier is max(old, new capability's tier).
    #[test]
    fn adding_a_capability_never_lowers_the_implied_tier(
        caps in arb_caps(),
        extra in arb_cap(),
    ) {
        // Declare tier 5 (native) so both manifests validate and expose `implied_tier`.
        let before = validate(manifest(5, &caps))
            .map_err(|e| TestCaseError::fail(format!("base rejected: {e}")))?
            .implied_tier;
        let mut more = caps.clone();
        if more.iter().all(|c| c.key != extra.key) {
            more.push(extra.clone());
        }
        let after = validate(manifest(5, &more))
            .map_err(|e| TestCaseError::fail(format!("superset rejected: {e}")))?
            .implied_tier;
        prop_assert!(after >= before, "{:?} < {:?}", after, before);
        prop_assert_eq!(after, tier_of(expected_implied(&more)));
    }

    /// Raising the declared tier never turns an accepted manifest into a
    /// rejected one on tier grounds, and lowering it can only add rejections.
    #[test]
    fn acceptance_is_monotone_in_the_declared_tier(caps in arb_caps()) {
        let accepted: Vec<bool> = (1u8..=5)
            .map(|t| validate(manifest(t, &caps)).is_ok())
            .collect();
        for w in accepted.windows(2) {
            prop_assert!(!w[0] || w[1], "accepted at a lower tier but rejected at a higher: {:?}", accepted);
        }
    }
}
