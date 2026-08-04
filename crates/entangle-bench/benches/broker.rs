//! Capability-broker hot-path benchmarks.
//!
//! The grant path is a security boundary that every capability use crosses, so
//! it is benchmarked in four shapes:
//!   * `grant_revoke` — the uncontended grant/release round trip.
//!   * `grant_denied` — the deny-by-default rejection path (error + audit).
//!   * `grant_revoke_contended` — the same round trip from N threads, which is
//!     what exposes how long the broker's write lock is actually held.
//!   * `audit_record` / `snapshot_grants` — the two supporting costs the grant
//!     path pays into.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use entangle_broker::{
    audit::{AuditEvent, AuditLog},
    broker::Broker,
    policy::BrokerPolicy,
};
use entangle_manifest::{
    schema::{BuildSection, Manifest, PluginSection, Runtime},
    validate::validate,
};
use entangle_types::{capability::CapabilityKind, plugin_id::PluginId, tier::Tier};
use std::hint::black_box;

const PUB: &str = "aabbccddeeff00112233445566778899";

fn fresh_manifest(name: &str) -> entangle_manifest::validate::ValidatedManifest {
    manifest_with(name, &["compute.cpu"])
}

fn manifest_with(name: &str, caps: &[&str]) -> entangle_manifest::validate::ValidatedManifest {
    let m = Manifest {
        plugin: PluginSection {
            id: format!("{PUB}/{name}@0.1.0"),
            version: semver::Version::parse("0.1.0").unwrap(),
            tier: 3,
            runtime: Runtime::Wasm,
            description: String::new(),
        },
        capabilities: {
            let mut map = std::collections::BTreeMap::new();
            for cap in caps {
                map.insert(cap.to_string(), toml::Value::Table(Default::default()));
            }
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

/// The deny path: an undeclared capability must be refused *and* audited.
/// Kept separate from the happy path because a misbehaving or probing plugin
/// drives this branch, and it must not become a cheap way to spam the daemon.
fn bench_grant_denied(c: &mut Criterion) {
    let plugin_id: PluginId = format!("{PUB}/deny-plugin@0.1.0").parse().unwrap();

    let mut group = c.benchmark_group("broker");
    group.bench_function(BenchmarkId::new("grant_denied", "10k"), |b| {
        b.iter(|| {
            let broker = Broker::new(BrokerPolicy::default());
            broker
                .register_plugin(fresh_manifest("deny-plugin"))
                .expect("register");
            for _ in 0..10_000u32 {
                let err = broker.grant(&plugin_id, &CapabilityKind::NetWan);
                black_box(err.is_err());
            }
        });
    });
    group.finish();
}

/// Grant/release from several threads at once against a single broker.
///
/// The broker serialises all grants behind one write lock, so this measures
/// exactly the work done *inside* that critical section — the number that
/// determines how well a multi-plugin daemon scales.
fn bench_grant_revoke_contended(c: &mut Criterion) {
    const THREADS: usize = 4;
    const PER_THREAD: u32 = 2_000;

    let plugin_id: PluginId = format!("{PUB}/bench-plugin@0.1.0").parse().unwrap();

    let mut group = c.benchmark_group("broker");
    group.sample_size(20);
    group.bench_function(BenchmarkId::new("grant_revoke_contended", "4x2k"), |b| {
        b.iter(|| {
            let broker = Broker::new(BrokerPolicy::default());
            broker
                .register_plugin(fresh_manifest("bench-plugin"))
                .expect("register");
            std::thread::scope(|s| {
                for _ in 0..THREADS {
                    let broker = &broker;
                    let plugin_id = &plugin_id;
                    s.spawn(move || {
                        for _ in 0..PER_THREAD {
                            let gc = broker
                                .grant(plugin_id, &CapabilityKind::ComputeCpu)
                                .expect("grant");
                            broker.release(plugin_id, gc.grant_id).expect("release");
                        }
                    });
                }
            });
        });
    });
    group.finish();
}

/// `AuditLog::record` in the steady state — i.e. at capacity, where every
/// append also evicts. The bounded-log guarantee means this is the path a
/// long-running daemon spends all its time on.
fn bench_audit_record(c: &mut Criterion) {
    let plugin: PluginId = format!("{PUB}/audit-plugin@0.1.0").parse().unwrap();

    let mut group = c.benchmark_group("broker");
    group.bench_function(BenchmarkId::new("audit_record", "at_capacity"), |b| {
        let log = AuditLog::with_capacity(1_024);
        // Fill to capacity so every measured record() also evicts.
        for i in 0..1_024u64 {
            log.record(AuditEvent::CapabilityGranted {
                plugin: plugin.clone(),
                capability: "compute.cpu".into(),
                grant_id: i,
                at: std::time::SystemTime::UNIX_EPOCH,
            });
        }
        let mut n = 0u64;
        b.iter(|| {
            n += 1;
            log.record(AuditEvent::CapabilityGranted {
                plugin: plugin.clone(),
                capability: "compute.cpu".into(),
                grant_id: n,
                at: std::time::SystemTime::UNIX_EPOCH,
            });
        });
    });
    group.finish();
}

/// Snapshotting outstanding grants — used by `entangle perms` and by the
/// scheduler when it needs a plugin's live capability set.
fn bench_snapshot_grants(c: &mut Criterion) {
    let plugin_id: PluginId = format!("{PUB}/snap-plugin@0.1.0").parse().unwrap();

    let broker = Broker::new(BrokerPolicy {
        max_tier_allowed: Tier::Native,
        ..Default::default()
    });
    broker
        .register_plugin(manifest_with(
            "snap-plugin",
            &["compute.cpu", "net.lan", "net.wan"],
        ))
        .expect("register");
    for _ in 0..100 {
        broker
            .grant(&plugin_id, &CapabilityKind::ComputeCpu)
            .expect("grant");
    }

    let mut group = c.benchmark_group("broker");
    group.bench_function(BenchmarkId::new("snapshot_grants", "100"), |b| {
        b.iter(|| black_box(broker.snapshot_grants(&plugin_id).len()));
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_grant_revoke,
    bench_grant_denied,
    bench_grant_revoke_contended,
    bench_audit_record,
    bench_snapshot_grants
);
criterion_main!(benches);
