/// Kernel hot-path benchmarks: manifest validation, plugin instantiate, plugin invoke.
///
/// The plugin benchmarks require the hello-pong fixture wasm to be present at:
///   crates/entangle-host/tests/fixtures/hello-pong.wasm
///
/// If missing, both benchmarks are skipped with a diagnostic message.
/// Build the fixture with: `cargo xtask hello-world build`
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use entangle_host::{engine::HostEngine, plugin::LoadedPlugin};
use entangle_manifest::{
    schema::{BuildSection, Manifest, PluginSection, Runtime},
    validate::validate,
};
use entangle_types::{plugin_id::PluginId, tier::Tier};

const PUB: &str = "aabbccddeeff00112233445566778899";

// ---------------------------------------------------------------------------
// Fixture path
// ---------------------------------------------------------------------------

fn fixture_wasm() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR = crates/entangle-bench
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent() // crates/
        .unwrap()
        .join("entangle-host/tests/fixtures/hello-pong.wasm")
}

// ---------------------------------------------------------------------------
// Manifest validation bench
// ---------------------------------------------------------------------------

fn bench_manifest_validate(c: &mut Criterion) {
    let mut group = c.benchmark_group("kernel");
    group.bench_function(BenchmarkId::new("manifest_validate", "5-caps"), |b| {
        b.iter(|| {
            let m = Manifest {
                plugin: PluginSection {
                    id: format!("{PUB}/bench-validate@0.1.0"),
                    version: semver::Version::parse("0.1.0").unwrap(),
                    tier: 3,
                    runtime: Runtime::Wasm,
                    description: String::new(),
                },
                capabilities: {
                    let mut map = std::collections::BTreeMap::new();
                    for cap in &[
                        "compute.cpu",
                        "compute.gpu",
                        "net.lan",
                        "net.wan",
                        "agent.invoke",
                    ] {
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
            let _ = std::hint::black_box(validate(m));
        });
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Plugin instantiate bench (1000x compile from bytes)
// ---------------------------------------------------------------------------

fn bench_plugin_instantiate(c: &mut Criterion) {
    let wasm_path = fixture_wasm();
    if !wasm_path.exists() {
        println!(
            "hello-pong fixture missing — run `cargo xtask hello-world build` first (expected: {wasm_path:?})"
        );
        return;
    }
    let wasm_bytes = std::fs::read(&wasm_path).expect("read fixture");
    let engine = HostEngine::new().expect("HostEngine::new");
    let plugin_id: PluginId = format!("{PUB}/hello-pong@0.1.0").parse().unwrap();

    let mut group = c.benchmark_group("kernel");
    group.bench_function(BenchmarkId::new("plugin_instantiate", "hello-pong"), |b| {
        b.iter(|| {
            let _ = std::hint::black_box(
                LoadedPlugin::from_bytes(&engine, &wasm_bytes, plugin_id.clone(), Tier::Sandboxed)
                    .expect("from_bytes"),
            );
        });
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Plugin invoke bench (1000x run_one_shot)
// ---------------------------------------------------------------------------

fn bench_plugin_invoke(c: &mut Criterion) {
    let wasm_path = fixture_wasm();
    if !wasm_path.exists() {
        println!(
            "hello-pong fixture missing — run `cargo xtask hello-world build` first (expected: {wasm_path:?})"
        );
        return;
    }
    let wasm_bytes = std::fs::read(&wasm_path).expect("read fixture");
    let engine = HostEngine::new().expect("HostEngine::new");
    let plugin_id: PluginId = format!("{PUB}/hello-pong@0.1.0").parse().unwrap();
    let plugin =
        LoadedPlugin::from_bytes(&engine, &wasm_bytes, plugin_id, Tier::Sandboxed).expect("load");

    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("kernel");
    group.bench_function(BenchmarkId::new("plugin_invoke", "hello-pong"), |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = std::hint::black_box(
                    plugin
                        .run_one_shot(&engine, b"world", 5_000)
                        .await
                        .expect("run_one_shot"),
                );
            });
        });
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Kernel::invoke — the orchestrated invoke path
// ---------------------------------------------------------------------------

/// Write a signed, loadable plugin package into `dir` and return its id string.
fn write_signed_package(
    dir: &std::path::Path,
    keypair: &entangle_signing::IdentityKeyPair,
    wasm_bytes: &[u8],
) -> String {
    let publisher = keypair.fingerprint_hex();
    let plugin_id_str = format!("{publisher}/bench-plugin@0.1.0");
    let manifest_toml = format!(
        r#"[plugin]
id = "{plugin_id_str}"
version = "0.1.0"
tier = 2
runtime = "wasm"
description = "kernel invoke benchmark plugin"

[capabilities]
"compute.cpu" = {{}}
"#
    );
    std::fs::write(dir.join("entangle.toml"), manifest_toml.as_bytes()).expect("write manifest");
    std::fs::write(dir.join("plugin.wasm"), wasm_bytes).expect("write wasm");
    let bundle = entangle_signing::sign_artifact(wasm_bytes, manifest_toml.as_bytes(), keypair);
    let sig_toml = toml::to_string(&bundle).expect("serialize bundle");
    std::fs::write(dir.join("plugin.wasm.sig"), sig_toml.as_bytes()).expect("write sig");
    plugin_id_str
}

/// `Kernel::invoke` end to end. Compared against `plugin_invoke` above (which
/// calls the host directly) this isolates the kernel's per-invocation
/// bookkeeping: the plugin-table lookup plus the two lifecycle events.
fn bench_kernel_invoke(c: &mut Criterion) {
    use entangle_runtime::{Kernel, KernelConfig};
    use entangle_signing::{IdentityKeyPair, Keyring, TrustEntry};

    let wasm_path = fixture_wasm();
    if !wasm_path.exists() {
        println!(
            "hello-pong fixture missing — run `cargo xtask hello-world build` first (expected: {wasm_path:?})"
        );
        return;
    }
    let wasm_bytes = std::fs::read(&wasm_path).expect("read fixture");

    let keypair = IdentityKeyPair::generate();
    let mut keyring = Keyring::new();
    let pub_key = keypair.public();
    keyring.add(TrustEntry {
        fingerprint: pub_key.fingerprint(),
        public_key: *pub_key.as_bytes(),
        publisher_name: "bench".into(),
        added_at: 0,
        note: String::new(),
    });

    let dir = tempfile::tempdir().expect("tempdir");
    let plugin_id_str = write_signed_package(dir.path(), &keypair, &wasm_bytes);
    let plugin_id: PluginId = plugin_id_str.parse().expect("plugin id");

    let rt = tokio::runtime::Runtime::new().unwrap();
    let kernel = Kernel::new(KernelConfig::default(), keyring).expect("kernel");
    rt.block_on(kernel.load_plugin_from_dir(dir.path()))
        .expect("load plugin");

    let mut group = c.benchmark_group("kernel");
    group.bench_function(BenchmarkId::new("kernel_invoke", "hello-pong"), |b| {
        b.iter(|| {
            rt.block_on(async {
                std::hint::black_box(
                    kernel
                        .invoke(&plugin_id, b"world", 5_000)
                        .await
                        .expect("invoke"),
                )
            })
        });
    });
    group.finish();
}

/// The kernel's lifecycle-event emit, isolated.
///
/// `Kernel::invoke` emits twice per call, but a wasm invocation costs ~55 us,
/// so a change worth a few hundred nanoseconds per emit sits far below the
/// noise floor of `kernel_invoke` above. These benchmarks therefore rebuild the
/// emit path out of the same public IPC API the kernel uses, in the two shapes
/// the kernel can be written in:
///
/// * `unconditional_*` — build the topic, build the envelope, publish. What
///   `Kernel::emit` used to do on every call.
/// * `guarded_*` — consult `Bus::subscriber_count` first and, when nothing is
///   listening, skip the whole thing; otherwise reuse a topic built once.
///   What `Kernel::emit` does now.
///
/// The `1_subscriber` variants deliberately never drain the subscriber: the
/// broadcast channel simply overwrites, which isolates the publish cost from
/// the receive cost.
fn bench_lifecycle_emit(c: &mut Criterion) {
    use entangle_ipc::{Bus, Envelope, Topic};
    use entangle_runtime::{LifecycleEvent, LifecyclePhase};

    const TOPIC: &str = "runtime.plugin.lifecycle";
    let plugin_id: PluginId = format!("{PUB}/bench-plugin@0.1.0").parse().unwrap();
    let evt = |plugin: &PluginId| LifecycleEvent {
        plugin: plugin.clone(),
        phase: LifecyclePhase::Activated,
        effective_tier: Tier::Sandboxed,
        at: std::time::SystemTime::now(),
    };

    let mut group = c.benchmark_group("kernel");

    for subscribers in [0usize, 1] {
        let label = if subscribers == 0 {
            "no_subscriber"
        } else {
            "1_subscriber"
        };

        group.bench_function(
            BenchmarkId::new("lifecycle_emit_unconditional", label),
            |b| {
                let bus: Bus<LifecycleEvent> = Bus::new(1024);
                let _subs: Vec<_> = (0..subscribers).map(|_| bus.subscribe()).collect();
                b.iter(|| {
                    let topic = Topic::new(TOPIC).expect("static topic is valid");
                    std::hint::black_box(bus.publish(Envelope::new(topic, evt(&plugin_id))).is_ok())
                });
            },
        );

        group.bench_function(BenchmarkId::new("lifecycle_emit_guarded", label), |b| {
            let bus: Bus<LifecycleEvent> = Bus::new(1024);
            let _subs: Vec<_> = (0..subscribers).map(|_| bus.subscribe()).collect();
            let topic = Topic::new(TOPIC).expect("static topic is valid");
            b.iter(|| {
                if bus.subscriber_count() == 0 {
                    return std::hint::black_box(false);
                }
                std::hint::black_box(
                    bus.publish(Envelope::new(topic.clone(), evt(&plugin_id)))
                        .is_ok(),
                )
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_manifest_validate,
    bench_plugin_instantiate,
    bench_plugin_invoke,
    bench_kernel_invoke,
    bench_lifecycle_emit
);
criterion_main!(benches);
