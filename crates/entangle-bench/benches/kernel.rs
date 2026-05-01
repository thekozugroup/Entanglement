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

criterion_group!(
    benches,
    bench_manifest_validate,
    bench_plugin_instantiate,
    bench_plugin_invoke
);
criterion_main!(benches);
