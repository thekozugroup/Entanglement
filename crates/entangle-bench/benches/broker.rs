use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use entangle_broker::{broker::Broker, policy::BrokerPolicy};
use entangle_manifest::{
    schema::{BuildSection, Manifest, PluginSection, Runtime},
    validate::validate,
};
use entangle_types::{capability::CapabilityKind, plugin_id::PluginId};

const PUB: &str = "aabbccddeeff00112233445566778899";

fn fresh_manifest(name: &str) -> entangle_manifest::validate::ValidatedManifest {
    let m = Manifest {
        plugin: PluginSection {
            id: format!("{PUB}/{name}@0.1.0"),
            version: semver::Version::parse("0.1.0").unwrap(),
            tier: 2,
            runtime: Runtime::Wasm,
            description: String::new(),
        },
        capabilities: {
            let mut map = std::collections::BTreeMap::new();
            map.insert(
                "compute.cpu".to_string(),
                toml::Value::Table(Default::default()),
            );
            map
        },
        build: Some(BuildSection {
            wit_world: None,
            target: None,
        }),
        signature: None,
    };
    validate(m).expect("test manifest must be valid")
}

fn bench_grant_revoke(c: &mut Criterion) {
    let plugin_id: PluginId = format!("{PUB}/bench-plugin@0.1.0").parse().unwrap();

    let mut group = c.benchmark_group("broker");
    // Each iter creates a broker, registers the plugin, then does 10 000 grant/release
    // round-trips.  The Broker is cheap to construct so this accurately measures
    // the grant/release fast path amortised across 10 000 cycles.
    group.bench_function(BenchmarkId::new("grant_revoke", "10k"), |b| {
        b.iter(|| {
            let broker = Broker::new(BrokerPolicy::default());
            broker
                .register_plugin(fresh_manifest("bench-plugin"))
                .expect("register");
            for _ in 0..10_000u32 {
                let gc = broker
                    .grant(&plugin_id, &CapabilityKind::ComputeCpu)
                    .expect("grant");
                broker.release(&plugin_id, gc.grant_id).expect("release");
            }
        });
    });
    group.finish();
}

criterion_group!(benches, bench_grant_revoke);
criterion_main!(benches);
