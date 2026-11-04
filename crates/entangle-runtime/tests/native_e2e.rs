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
use entangle_types::capability::{CapabilityKind, StorageMode, StorageScope};
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
            scope: StorageScope::Plugin,
            mode: StorageMode::Rw,
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

/// A share name is one directory under `<data>/shares`. A signed manifest
/// naming `/` or `../..` (the daemon's config directory, holding its identity
/// key and keyring) must be refused at load — before any grant, staging copy
/// or directory exists — not turned into a Landlock rule on that path.
#[tokio::test(flavor = "multi_thread")]
async fn a_share_name_outside_the_shares_directory_is_refused_at_load() {
    for (caps, label) in [
        ("\"storage.share./\" = { mode = \"rw\" }", "/"),
        ("\"storage.share.../..\" = { mode = \"ro\" }", "../.."),
        ("\"storage.share..\" = { mode = \"rw\" }", "."),
    ] {
        let kp = IdentityKeyPair::generate();
        let e = env();
        // The manifest is refused before the artifact is examined.
        write_package(
            &e.pkg,
            &kp,
            b"\x7fELF\x02\x01\x01",
            "plugin.bin",
            5,
            "native",
            caps,
        );
        let k = kernel(&e, &kp, Tier::Native);
        match k.load_plugin_from_dir(&e.pkg).await {
            Ok(id) => panic!(
                "share {label:?} loaded; grants {:?}, sandbox profile {:?}",
                k.broker().snapshot_grants(&id),
                k.native_sandbox(&id).map(|p| p.describe())
            ),
            Err(err) => assert!(err.to_string().contains("share name"), "{label}: {err}"),
        }
        assert!(k.list_plugins().is_empty());
        assert!(
            k.broker().audit_log().is_empty(),
            "{label}: no broker events"
        );
        assert!(!e.staging.exists(), "{label}: nothing staged");
        assert!(!e.data.exists(), "{label}: no storage scope created");
    }
}

/// `p` (absolute) spelled relative to the current working directory, e.g.
/// `../../../../tmp/.tmpXYZ/pkg`, without changing the process-wide cwd.
fn relative_to_cwd(p: &Path) -> PathBuf {
    let cwd = std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
    let mut rel = PathBuf::new();
    for _ in cwd.components().skip(1) {
        rel.push("..");
    }
    rel.join(p.strip_prefix("/").unwrap())
}

/// A package directory, data directory or staging root given relative to
/// the daemon's working directory (`entangle plugins load h/.entangle/...`,
/// a relative `$HOME`) must yield a plugin that runs — not one that loads,
/// is listed and holds its grants, then fails every invocation with
/// `ENTANGLE-E0704: path ... is not absolute`.
#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_loaded_through_relative_paths_invokes() {
    let kp = IdentityKeyPair::generate();
    let e = env();
    let bin = std::fs::read(native_echo_binary()).unwrap();
    write_package(&e.pkg, &kp, &bin, "plugin.bin", 5, "native", STORAGE);
    let root = std::fs::canonicalize(e._tmp.path()).unwrap();
    let k = Kernel::new(
        KernelConfig {
            native: NativeConfig {
                data_dir: Some(relative_to_cwd(&root.join("data"))),
                staging_dir: Some(relative_to_cwd(&root.join("staging"))),
                ..NativeConfig::default()
            },
            ..KernelConfig::default()
        },
        keyring_for(&kp),
    )
    .unwrap();
    let rel_pkg = relative_to_cwd(&root.join("pkg"));
    assert!(
        rel_pkg.is_relative() && rel_pkg.is_dir(),
        "{}",
        rel_pkg.display()
    );

    let id = k.load_plugin_from_dir(&rel_pkg).await.expect("load");
    let out = k
        .invoke(&id, b"relative", 10_000)
        .await
        .expect("a plugin that loaded must also run");
    assert_eq!(out, b"relative");
    // Its scope landed where the absolute configuration would put it.
    let own = e
        .data
        .join("plugins")
        .join(kp.fingerprint_hex())
        .join("native-echo");
    assert_eq!(std::fs::read_to_string(own.join("requests")).unwrap(), "1");
    k.unload(&id).await.unwrap();
}

/// Set (to a scratch root) only when
/// `stale_staging_copies_are_swept_when_a_kernel_starts` re-runs this test
/// binary as a child process.
const STAGE_AND_EXIT: &str = "ENTANGLE_E2E_STAGE_AND_EXIT";

/// Child-process half of `stale_staging_copies_are_swept_when_a_kernel_starts`.
/// With [`STAGE_AND_EXIT`] set it loads a native plugin, staging it under
/// `<root>/staging`, and exits without unloading — as a SIGKILLed or
/// OOM-killed daemon would: no destructor runs, and the OS releases whatever
/// the process held. Without the variable (every ordinary run) it does
/// nothing.
#[tokio::test(flavor = "multi_thread")]
async fn child_loads_a_native_plugin_then_exits_without_unloading() {
    let Some(root) = std::env::var_os(STAGE_AND_EXIT).map(PathBuf::from) else {
        return;
    };
    let kp = IdentityKeyPair::generate();
    let pkg = root.join("child-pkg");
    std::fs::create_dir_all(&pkg).unwrap();
    // Loading stages the bytes; they are never executed here.
    write_package(
        &pkg,
        &kp,
        b"\x7fELF\x02\x01\x01",
        "plugin.bin",
        5,
        "native",
        "",
    );
    let k = Kernel::new(
        KernelConfig {
            native: NativeConfig {
                data_dir: Some(root.join("data")),
                staging_dir: Some(root.join("staging")),
                ..NativeConfig::default()
            },
            ..KernelConfig::default()
        },
        keyring_for(&kp),
    )
    .unwrap();
    k.load_plugin_from_dir(&pkg).await.expect("child load");
    std::process::exit(0);
}

/// A daemon killed with plugins loaded leaves each staged binary behind.
/// The next kernel to start on that staging root — the daemon restarting,
/// or the CLI's local kernel, which shares `~/.entangle/native` with a
/// running daemon — removes those copies, and only those: a copy a live
/// kernel is using stays and keeps running.
#[tokio::test(flavor = "multi_thread")]
async fn stale_staging_copies_are_swept_when_a_kernel_starts() {
    let kp = IdentityKeyPair::generate();
    let e = env();
    let bin = std::fs::read(native_echo_binary()).unwrap();
    write_package(&e.pkg, &kp, &bin, "plugin.bin", 5, "native", "");

    // A kernel that stays up with a plugin loaded …
    let live = kernel(&e, &kp, Tier::Native);
    let id = live.load_plugin_from_dir(&e.pkg).await.expect("load");
    assert_eq!(entries(&e.staging), 1);

    // … and a process that staged into the same root and was killed.
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_loads_a_native_plugin_then_exits_without_unloading",
            "--nocapture",
        ])
        .env(STAGE_AND_EXIT, e._tmp.path())
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "child failed: {}\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    assert_eq!(
        entries(&e.staging),
        2,
        "the killed process left its staged copy behind"
    );

    // The next kernel to start on that root sweeps the dead copy only.
    let _next = kernel(&e, &kp, Tier::Native);
    assert_eq!(
        entries(&e.staging),
        1,
        "the copy of the process that died is removed; the live one stays"
    );
    let out = live
        .invoke(&id, b"still staged", 10_000)
        .await
        .expect("the live kernel's staged copy was kept");
    assert_eq!(out, b"still staged");
    live.unload(&id).await.unwrap();
    assert_eq!(entries(&e.staging), 0);
}
