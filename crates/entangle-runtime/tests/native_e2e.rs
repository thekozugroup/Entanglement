//! End-to-end for tier-5 native plugins: build `examples/native-echo` with
//! cargo, sign it, load it through the kernel, and invoke it under the real
//! OS sandbox this host offers.
//!
//! Linux-only: the macOS Seatbelt path is smoke-tested in
//! `entangle-sandbox/tests/seatbelt_smoke.rs`.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use entangle_broker::{AuditKind, PolicyError};
use entangle_host::{ArtifactKind, DeclaredRuntime, HostError};
use entangle_runtime::{Kernel, KernelConfig, NativeConfig, RuntimeError};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::capability::{CapabilityKind, StorageScope};
use entangle_types::tier::Tier;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

/// Build the example once per test binary (debug profile, separate target
/// dir so it never contends with the workspace build lock).
fn native_echo_binary() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let root = workspace_root();
        let target_dir = root.join("target").join("native-examples");
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
        let status = std::process::Command::new(cargo)
            .args(["build", "--quiet", "--manifest-path"])
            .arg(root.join("examples/native-echo/Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .status()
            .expect("run cargo build for examples/native-echo");
        assert!(status.success(), "building examples/native-echo failed");
        let bin = target_dir.join("debug").join("entangle-native-echo");
        assert!(bin.is_file(), "missing {}", bin.display());
        bin
    })
}

fn keyring_for(kp: &IdentityKeyPair) -> Keyring {
    let mut kr = Keyring::new();
    kr.add(TrustEntry {
        fingerprint: kp.fingerprint(),
        public_key: *kp.public().as_bytes(),
        publisher_name: "native-e2e".into(),
        added_at: 0,
        note: String::new(),
    });
    kr
}

/// Write a signed package; returns the plugin id.
fn write_package(
    dir: &Path,
    kp: &IdentityKeyPair,
    artifact: &[u8],
    artifact_name: &str,
    tier: u8,
    runtime: &str,
    caps: &str,
) -> String {
    let id = format!("{}/native-echo@0.1.0", kp.fingerprint_hex());
    let manifest = format!(
        "[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = {tier}\nruntime = \"{runtime}\"\n\
         description = \"e2e\"\n\n[capabilities]\n{caps}\n"
    );
    std::fs::write(dir.join("entangle.toml"), &manifest).unwrap();
    std::fs::write(dir.join(artifact_name), artifact).unwrap();
    let bundle = sign_artifact(artifact, manifest.as_bytes(), kp);
    std::fs::write(
        dir.join(format!("{artifact_name}.sig")),
        toml::to_string(&bundle).unwrap(),
    )
    .unwrap();
    id
}

struct Env {
    _tmp: tempfile::TempDir,
    pkg: PathBuf,
    data: PathBuf,
    staging: PathBuf,
}

fn env() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("pkg");
    let data = tmp.path().join("data");
    let staging = tmp.path().join("staging");
    std::fs::create_dir_all(&pkg).unwrap();
    Env {
        pkg,
        data,
        staging,
        _tmp: tmp,
    }
}

fn kernel(e: &Env, kp: &IdentityKeyPair, max_tier: Tier) -> Kernel {
    Kernel::new(
        KernelConfig {
            max_tier_allowed: max_tier,
            native: NativeConfig {
                data_dir: Some(e.data.clone()),
                staging_dir: Some(e.staging.clone()),
                ..NativeConfig::default()
            },
            ..KernelConfig::default()
        },
        keyring_for(kp),
    )
    .unwrap()
}

fn entries(dir: &Path) -> usize {
    std::fs::read_dir(dir).map(|d| d.count()).unwrap_or(0)
}

const STORAGE: &str = "\"storage.local\" = { scope = \"plugin\" }";

#[tokio::test(flavor = "multi_thread")]
async fn native_plugin_loads_and_invokes_through_the_kernel() {
    let kp = IdentityKeyPair::generate();
    let e = env();
    let bin = std::fs::read(native_echo_binary()).unwrap();
    write_package(&e.pkg, &kp, &bin, "plugin.bin", 5, "native", STORAGE);
    let k = kernel(&e, &kp, Tier::Native);

    let id = k.load_plugin_from_dir(&e.pkg).await.expect("native load");
    assert_eq!(k.list_plugins(), vec![id.clone()]);

    // The sandbox that will be engaged is the full one on this host, and the
    // plugin has no network (it was not granted any).
    let plan = k
        .native_sandbox(&id)
        .expect("native plugin has a sandbox plan");
    // Not degraded wherever the host offers the full set of layers. Below
    // Landlock ABI 6 (CI's ubuntu-24.04 kernel) signals are not scoped, and a
    // host without seccomp leaves Unix sockets unfiltered: the plan must then
    // say "reduced", and it does.
    let host = entangle_sandbox::probe();
    let full_host = host.landlock_abi.is_some_and(|abi| abi >= 6) && host.seccomp;
    assert_eq!(plan.is_degraded(), !full_host, "{}", plan.describe());
    assert_eq!(
        plan.network,
        entangle_sandbox::NetworkIsolation::Denied,
        "{}",
        plan.describe()
    );

    // The capability was granted through the broker (audited).
    let grants = k.broker().snapshot_grants(&id);
    assert_eq!(grants.len(), 1);
    assert_eq!(
        grants[0].kind,
        CapabilityKind::StorageLocal {
            scope: StorageScope::Plugin
        }
    );

    // The binary is staged privately, not run from the package directory.
    assert_eq!(entries(&e.staging), 1);

    let out = k
        .invoke(&id, b"hello sandbox", 10_000)
        .await
        .expect("invoke");
    assert_eq!(out, b"hello sandbox");
    let out = k
        .invoke(&id, &[0, 159, 255], 10_000)
        .await
        .expect("binary invoke");
    assert_eq!(out, vec![0, 159, 255]);

    // It wrote inside its own storage scope — and only there.
    let own = e
        .data
        .join("plugins")
        .join(kp.fingerprint_hex())
        .join("native-echo");
    assert_eq!(std::fs::read_to_string(own.join("requests")).unwrap(), "2");

    k.unload(&id).await.unwrap();
    assert!(k.list_plugins().is_empty());
    assert!(k.broker().snapshot_grants(&id).is_empty());
    assert_eq!(entries(&e.staging), 0, "staging copy removed on unload");
}

#[tokio::test(flavor = "multi_thread")]
async fn declared_native_but_artifact_is_wasm_is_rejected_without_state() {
    let kp = IdentityKeyPair::generate();
    let e = env();
    let wasm =
        std::fs::read(workspace_root().join("crates/entangle-host/tests/fixtures/hello-pong.wasm"))
            .unwrap();
    write_package(&e.pkg, &kp, &wasm, "plugin.bin", 5, "native", "");
    let k = kernel(&e, &kp, Tier::Native);

    let err = k.load_plugin_from_dir(&e.pkg).await.unwrap_err();
    assert!(
        matches!(
            err,
            RuntimeError::Host(HostError::RuntimeKindMismatch {
                declared: DeclaredRuntime::Native,
                observed: ArtifactKind::WasmComponent
            })
        ),
        "{err}"
    );
    assert!(k.list_plugins().is_empty());
    assert_eq!(entries(&e.staging), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn wasm_manifest_shipping_a_native_binary_is_rejected() {
    let kp = IdentityKeyPair::generate();
    let e = env();
    let bin = std::fs::read(native_echo_binary()).unwrap();
    // Named plugin.wasm, declared wasm, tier 1 — but it is an ELF.
    write_package(&e.pkg, &kp, &bin, "plugin.wasm", 1, "wasm", "");
    let k = kernel(&e, &kp, Tier::Native);
    let err = k.load_plugin_from_dir(&e.pkg).await.unwrap_err();
    assert!(
        matches!(
            err,
            RuntimeError::Host(HostError::RuntimeKindMismatch {
                declared: DeclaredRuntime::Wasm,
                observed: ArtifactKind::Elf
            })
        ),
        "{err}"
    );
    assert!(k.list_plugins().is_empty());
}

/// `max_tier_allowed = 4` is the one config line that disables tier-5
/// plugins: refused before signature work, grants, or any file write.
#[tokio::test(flavor = "multi_thread")]
async fn tier_ceiling_refuses_native_before_any_state_exists() {
    let kp = IdentityKeyPair::generate();
    let e = env();
    let bin = std::fs::read(native_echo_binary()).unwrap();
    write_package(&e.pkg, &kp, &bin, "plugin.bin", 5, "native", STORAGE);
    let k = kernel(&e, &kp, Tier::Privileged);

    let err = k.load_plugin_from_dir(&e.pkg).await.unwrap_err();
    assert!(
        matches!(
            err,
            RuntimeError::Broker(entangle_broker::BrokerError::Policy(
                PolicyError::TierAboveCeiling {
                    plugin: Tier::Native,
                    ceiling: Tier::Privileged
                }
            ))
        ),
        "{err}"
    );
    assert!(err.to_string().contains("ENTANGLE-E0043"), "{err}");
    assert!(k.list_plugins().is_empty());
    assert!(k.broker().audit_log().is_empty(), "no broker events");
    assert!(!e.staging.exists(), "nothing staged");
    assert!(!e.data.exists(), "no storage scope created");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_native_binary_altered_after_signing_is_rejected() {
    let kp = IdentityKeyPair::generate();
    let e = env();
    let mut bin = std::fs::read(native_echo_binary()).unwrap();
    write_package(&e.pkg, &kp, &bin, "plugin.bin", 5, "native", "");
    let last = bin.len() - 1;
    bin[last] ^= 0xFF;
    std::fs::write(e.pkg.join("plugin.bin"), &bin).unwrap();
    let k = kernel(&e, &kp, Tier::Native);
    let err = k.load_plugin_from_dir(&e.pkg).await.unwrap_err();
    assert!(matches!(err, RuntimeError::Signing(_)), "{err}");
    assert!(!e.staging.exists());
    assert!(!k
        .broker()
        .audit_log()
        .snapshot()
        .iter()
        .any(|ev| ev.kind() == AuditKind::PluginRegistered));
}
