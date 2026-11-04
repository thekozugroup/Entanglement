//! The broker's metrics: grants, denials and biscuit verification latency are
//! counted with a fixed-cardinality `capability` label.

use biscuit_auth::KeyPair as BiscuitKp;
use entangle_biscuits::claims::ClaimSet;
use entangle_broker::{
    policy::{BrokerPolicy, CrossNodePolicy},
    Broker,
};
use entangle_manifest::{
    schema::{BuildSection, Manifest, PluginSection, Runtime},
    validate::validate,
    ValidatedManifest,
};
use entangle_observability::catalog::names;
use entangle_observability::Registry;
use entangle_types::{capability::CapabilityKind, peer_id::PeerId};
use std::time::{SystemTime, UNIX_EPOCH};

const PUB: &str = "aabbccddeeff00112233445566778899";

fn manifest(name: &str, caps: &[&str]) -> ValidatedManifest {
    let mut m = Manifest {
        plugin: PluginSection {
            id: format!("{PUB}/{name}@0.1.0"),
            version: semver::Version::parse("0.1.0").unwrap(),
            tier: 3,
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

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[test]
fn grants_and_denials_are_counted_by_capability_kind() {
    let registry = Registry::new();
    let broker = Broker::new(BrokerPolicy::default()).with_metrics(registry.clone());
    let m = manifest("metrics-plugin", &["compute.cpu"]);
    let id = m.plugin_id.clone();
    broker.register_plugin(m).unwrap();

    broker.grant(&id, &CapabilityKind::ComputeCpu).unwrap();
    broker.grant(&id, &CapabilityKind::ComputeCpu).unwrap();
    // Undeclared: denied. A parameterised kind folds to its family, so a
    // plugin cannot mint label values through share names or custom strings.
    for kind in [
        CapabilityKind::NetWan { hosts: vec![] },
        CapabilityKind::Custom("a-very-specific-thing".into()),
        CapabilityKind::Custom("another".into()),
    ] {
        broker.grant(&id, &kind).unwrap_err();
    }

    assert_eq!(
        registry.value(names::CAPABILITY_GRANTS, &[("capability", "compute.cpu")]),
        Some(2.0)
    );
    assert_eq!(
        registry.value(
            names::CAPABILITY_DENIALS,
            &[("capability", "net.wan"), ("reason", "not_declared")]
        ),
        Some(1.0)
    );
    assert_eq!(
        registry.value(
            names::CAPABILITY_DENIALS,
            &[("capability", "custom"), ("reason", "not_declared")]
        ),
        Some(2.0)
    );
    let text = registry.render();
    assert!(!text.contains("a-very-specific-thing"), "{text}");
}

#[test]
fn biscuit_verification_latency_is_recorded_for_both_outcomes() {
    let registry = Registry::new();
    let broker = Broker::new(BrokerPolicy::default()).with_metrics(registry.clone());
    let m = manifest("biscuit-metrics", &["compute.cpu"]);
    let id = m.plugin_id.clone();
    broker.register_plugin(m).unwrap();

    let kp = BiscuitKp::new();
    let local = PeerId::from_hex("00000000000000000000000000000009").unwrap();
    let policy = CrossNodePolicy::empty().with_root(kp.public());
    let claims = ClaimSet::new()
        .issued_to(local)
        .capability("compute.cpu")
        .expires(now() + 3600);
    let good = entangle_biscuits::mint::mint(&kp, &claims).unwrap();
    broker
        .grant_with_biscuit(&id, &CapabilityKind::ComputeCpu, &good, local, &policy)
        .unwrap();
    // Signed by a key nobody trusts.
    let forged = entangle_biscuits::mint::mint(&BiscuitKp::new(), &claims).unwrap();
    broker
        .grant_with_biscuit(&id, &CapabilityKind::ComputeCpu, &forged, local, &policy)
        .unwrap_err();

    assert_eq!(
        registry.value(names::BISCUIT_VERIFY, &[("outcome", "ok")]),
        Some(1.0),
        "histogram count"
    );
    assert_eq!(
        registry.value(names::BISCUIT_VERIFY, &[("outcome", "denied")]),
        Some(1.0)
    );
    assert_eq!(
        registry.value(
            names::CAPABILITY_DENIALS,
            &[("capability", "compute.cpu"), ("reason", "biscuit_invalid")]
        ),
        Some(1.0)
    );
    // The successful biscuit also produced a normal grant.
    assert_eq!(
        registry.value(names::CAPABILITY_GRANTS, &[("capability", "compute.cpu")]),
        Some(1.0)
    );
    let text = registry.render();
    assert!(
        text.contains("entangle_biscuit_verification_seconds_bucket{outcome=\"ok\",le=\"+Inf\"} 1"),
        "{text}"
    );
}

#[test]
fn a_broker_without_metrics_behaves_like_an_instrumented_one() {
    // Control: an instrumented broker records exactly one grant.
    let registry = Registry::new();
    let metered = Broker::new(BrokerPolicy::default()).with_metrics(registry.clone());
    let plain = Broker::new(BrokerPolicy::default());
    let m = manifest("quiet", &["compute.cpu"]);
    let id = m.plugin_id.clone();
    metered.register_plugin(m).unwrap();
    plain
        .register_plugin(manifest("quiet", &["compute.cpu"]))
        .unwrap();

    let a = metered.grant(&id, &CapabilityKind::ComputeCpu);
    let b = plain.grant(&id, &CapabilityKind::ComputeCpu);
    assert!(
        a.is_ok() && b.is_ok(),
        "same outcome with or without metrics"
    );
    assert_eq!(
        registry.value(names::CAPABILITY_GRANTS, &[("capability", "compute.cpu")]),
        Some(1.0),
        "the instrumented broker did record; the plain one has no registry to write to"
    );
    // A denial path on the plain broker must also work without a registry.
    let other = manifest("other", &[]);
    let oid = other.plugin_id.clone();
    plain.register_plugin(other).unwrap();
    assert!(plain.grant(&oid, &CapabilityKind::ComputeCpu).is_err());
    // The plain broker's activity never reached the instrumented one's registry.
    assert_eq!(
        registry.value(names::CAPABILITY_GRANTS, &[("capability", "compute.cpu")]),
        Some(1.0)
    );
    assert_eq!(
        registry.value(
            names::CAPABILITY_DENIALS,
            &[("capability", "compute.cpu"), ("reason", "not_declared")]
        ),
        None
    );
}
