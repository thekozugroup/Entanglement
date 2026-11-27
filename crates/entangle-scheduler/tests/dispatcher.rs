//! Integration tests for the Dispatcher.

use entangle_runtime::{Kernel, KernelConfig};
use entangle_scheduler::{DispatchError, Dispatcher, WorkerInfo, WorkerPool};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::{
    peer_id::PeerId,
    resource::{GpuBackend, GpuRequirement, NpuRequirement, ResourceSpec},
    task::{IntegrityPolicy, OneShotTask},
};
use std::sync::Arc;

// ── helpers ──────────────────────────────────────────────────────────────────

fn build_keyring(keypair: &IdentityKeyPair) -> Keyring {
    let pub_key = keypair.public();
    let entry = TrustEntry {
        fingerprint: pub_key.fingerprint(),
        public_key: *pub_key.as_bytes(),
        publisher_name: "test-publisher".into(),
        added_at: 0,
        note: String::new(),
    };
    let mut kr = Keyring::new();
    kr.add(entry);
    kr
}

fn local_peer() -> PeerId {
    PeerId::from_public_key_bytes(&[0xab; 32])
}

/// Path to the committed hello-pong fixture — a real WASM component whose
/// `run` export echoes `Hello, <input>!`.
const HELLO_PONG_WASM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../entangle-host/tests/fixtures/hello-pong.wasm"
);

/// Read the hello-pong fixture. The fixture is checked into the repository, so
/// a missing file is a hard failure rather than a silent skip.
fn hello_pong_wasm() -> Vec<u8> {
    std::fs::read(HELLO_PONG_WASM)
        .expect("hello-pong.wasm fixture not found — run fixtures-src/hello-pong/build.sh")
}

/// Write a signed plugin package (manifest + wasm + sig) into `dir`.
///
/// Returns the plugin id string.
fn write_plugin_package(
    dir: &std::path::Path,
    keypair: &IdentityKeyPair,
    wasm_bytes: &[u8],
) -> String {
    let publisher = keypair.fingerprint_hex();
    let plugin_id_str = format!("{publisher}/test-plugin@0.1.0");

    let manifest_toml = format!(
        r#"[plugin]
id = "{plugin_id_str}"
version = "0.1.0"
tier = 1
runtime = "wasm"
description = "scheduler integration test plugin"
"#
    );

    std::fs::write(dir.join("entangle.toml"), manifest_toml.as_bytes()).expect("write manifest");
    std::fs::write(dir.join("plugin.wasm"), wasm_bytes).expect("write wasm");

    let bundle = sign_artifact(wasm_bytes, manifest_toml.as_bytes(), keypair);
    let sig_toml = toml::to_string(&bundle).expect("serialize bundle");
    std::fs::write(dir.join("plugin.wasm.sig"), sig_toml.as_bytes()).expect("write sig");

    plugin_id_str
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// Dispatch with an empty pool and no resource requirements falls back to the
/// local kernel and returns the plugin output.
///
/// Uses the hello-pong fixture which echos "Hello, <input>!".
#[tokio::test]
async fn dispatch_with_empty_pool_falls_back_to_local_when_no_resources_required() {
    let wasm = hello_pong_wasm();

    let keypair = IdentityKeyPair::generate();
    let keyring = build_keyring(&keypair);

    let dir = tempfile::tempdir().expect("tempdir");
    let plugin_id_str = write_plugin_package(dir.path(), &keypair, &wasm);
    let plugin_id: entangle_types::plugin_id::PluginId =
        plugin_id_str.parse().expect("parse plugin id");

    let kernel = Arc::new(Kernel::new(KernelConfig::default(), keyring).expect("kernel"));
    kernel
        .load_plugin_from_dir(dir.path())
        .await
        .expect("load ok");

    let pool = WorkerPool::new(); // empty — no workers
    let dispatcher = Dispatcher::new(pool, kernel, local_peer());

    let task = OneShotTask {
        id: uuid::Uuid::new_v4(),
        plugin: plugin_id,
        input: b"world".to_vec(),
        max_input_bytes: OneShotTask::DEFAULT_MAX_INPUT_BYTES,
        max_output_bytes: OneShotTask::DEFAULT_MAX_OUTPUT_BYTES,
        resources: ResourceSpec::default(), // zero resources → triggers local fallback
        integrity: entangle_types::task::IntegrityPolicy::None,
        timeout_ms: 30_000,
    };

    let result = dispatcher
        .dispatch_one_shot(task)
        .await
        .expect("dispatch ok");
    assert_eq!(result.output, b"Hello, world!");
}

fn make_remote_worker(byte: u8) -> WorkerInfo {
    WorkerInfo {
        peer_id: PeerId::from_public_key_bytes(&[byte; 32]),
        display_name: "remote-node".into(),
        cpu_cores: 16.0,
        memory_bytes: 64 * 1024 * 1024 * 1024,
        gpu: None,
        npu: None,
        network_bandwidth_bps: 1_000_000_000,
        rtt_ms: 1,
        load: 0.0,
        cost: 1.0,
    }
}

#[tokio::test]
async fn placement_scores_local_hardware_only_while_the_requested_plugin_is_loaded() {
    let keypair = IdentityKeyPair::generate();
    let dir = tempfile::tempdir().unwrap();
    let plugin = write_plugin_package(dir.path(), &keypair, &hello_pong_wasm())
        .parse()
        .unwrap();
    let kernel = Arc::new(Kernel::new(KernelConfig::default(), build_keyring(&keypair)).unwrap());
    let pool = WorkerPool::new();
    let local = make_remote_worker(0xab);
    let mut remote = make_remote_worker(0x42);
    remote.cost = local.cost + 2.0;
    pool.upsert(remote.clone());
    let mut dispatcher = Dispatcher::new(pool.clone(), kernel.clone(), local_peer())
        .with_local_worker(local)
        .with_strict_remote(true);
    let mut task = OneShotTask::with_defaults(plugin, b"local".to_vec());
    task.resources.cpu_cores = 2.0;
    task.resources.memory_bytes = 1024;

    let err = dispatcher
        .dispatch_one_shot(task.clone())
        .await
        .unwrap_err();
    assert!(
        matches!(err, DispatchError::RemoteNotImplemented { peer, .. } if peer == remote.peer_id)
    );

    kernel.load_plugin_from_dir(dir.path()).await.unwrap();
    let result = dispatcher.dispatch_one_shot(task.clone()).await.unwrap();
    assert_eq!(result.chosen.peer_id, local_peer());
    assert_eq!(result.output, b"Hello, local!");

    // A better-scoring remote remains eligible while the local plugin is loaded.
    remote.cost = 0.0;
    pool.upsert(remote.clone());
    let err = dispatcher
        .dispatch_one_shot(task.clone())
        .await
        .unwrap_err();
    assert!(
        matches!(err, DispatchError::RemoteNotImplemented { peer, .. } if peer == remote.peer_id)
    );

    // A network observation claiming this node's ID cannot replace its known hardware.
    let mut stale_local = make_remote_worker(0xab);
    stale_local.cpu_cores = 64.0;
    pool.upsert(stale_local);
    task.resources.cpu_cores = 32.0;
    let err = dispatcher
        .dispatch_one_shot(task.clone())
        .await
        .unwrap_err();
    assert!(matches!(err, DispatchError::Placement(_)), "{err}");
    task.resources.cpu_cores = 2.0;

    // Only network observations expire. The local hardware persists independently.
    dispatcher.worker_ttl = std::time::Duration::ZERO;
    assert!(pool.live(dispatcher.worker_ttl).is_empty());
    assert_eq!(
        dispatcher
            .dispatch_one_shot(task.clone())
            .await
            .unwrap()
            .chosen
            .peer_id,
        local_peer()
    );

    task.resources.cpu_cores = 17.0;
    let err = dispatcher
        .dispatch_one_shot(task.clone())
        .await
        .unwrap_err();
    assert!(matches!(err, DispatchError::Placement(_)), "{err}");

    task.resources.cpu_cores = 2.0;
    kernel.unload(&task.plugin).await.unwrap();
    let err = dispatcher.dispatch_one_shot(task).await.unwrap_err();
    assert!(matches!(err, DispatchError::Placement(_)), "{err}");
}

/// In strict-remote mode the dispatcher refuses to silently rerun a remote
/// placement on the local kernel; it returns `RemoteNotImplemented`.
#[tokio::test]
async fn strict_remote_returns_not_implemented_when_placement_picks_remote_peer() {
    let keypair = IdentityKeyPair::generate();
    let keyring = build_keyring(&keypair);
    let kernel = Arc::new(Kernel::new(KernelConfig::default(), keyring).expect("kernel"));

    let pool = WorkerPool::new();
    pool.upsert(make_remote_worker(0x42));

    let plugin_id: entangle_types::plugin_id::PluginId =
        format!("{}/nothing@0.1.0", keypair.fingerprint_hex())
            .parse()
            .expect("parse plugin id");

    let dispatcher = Dispatcher::new(pool, kernel, local_peer()).with_strict_remote(true);

    let task = OneShotTask {
        id: uuid::Uuid::new_v4(),
        plugin: plugin_id,
        input: b"x".to_vec(),
        max_input_bytes: OneShotTask::DEFAULT_MAX_INPUT_BYTES,
        max_output_bytes: OneShotTask::DEFAULT_MAX_OUTPUT_BYTES,
        resources: ResourceSpec::default(),
        integrity: entangle_types::task::IntegrityPolicy::None,
        timeout_ms: 5_000,
    };

    let err = dispatcher
        .dispatch_one_shot(task)
        .await
        .expect_err("strict mode must reject remote placement");
    match err {
        DispatchError::RemoteNotImplemented { peer, reason } => {
            assert_eq!(peer, PeerId::from_public_key_bytes(&[0x42; 32]));
            assert!(
                !reason.is_empty(),
                "RemoteNotImplemented.reason must carry the placement reason"
            );
        }
        other => panic!("expected RemoteNotImplemented, got: {other:?}"),
    }
}

// ── integrity + size-limit enforcement ────────────────────────────────────────

/// Build a dispatcher over an empty pool and a plugin-less kernel. Suitable for
/// tests whose integrity/size checks fire *before* any plugin invocation
/// (empty pool + zero-resource task ⇒ local fallback ⇒ `invoke_with_integrity`).
fn empty_dispatcher(keypair: &IdentityKeyPair) -> Dispatcher {
    let keyring = build_keyring(keypair);
    let kernel = Arc::new(Kernel::new(KernelConfig::default(), keyring).expect("kernel"));
    Dispatcher::new(WorkerPool::new(), kernel, local_peer())
}

fn nothing_plugin_id(keypair: &IdentityKeyPair) -> entangle_types::plugin_id::PluginId {
    format!("{}/nothing@0.1.0", keypair.fingerprint_hex())
        .parse()
        .expect("parse plugin id")
}

#[tokio::test]
async fn fallback_requires_evidence_of_local_resources() {
    let keypair = IdentityKeyPair::generate();
    let kernel = Arc::new(Kernel::new(KernelConfig::default(), build_keyring(&keypair)).unwrap());
    let pool = WorkerPool::new();
    let dispatcher = Dispatcher::new(pool.clone(), kernel, local_peer());
    let gpu = GpuRequirement {
        backend: GpuBackend::Cuda,
        vram_min_bytes: 1024,
    };
    let npu = NpuRequirement {
        vendor: "apple".into(),
    };
    let mut task = OneShotTask::with_defaults(nothing_plugin_id(&keypair), vec![]);
    for resources in [
        ResourceSpec {
            gpu: Some(gpu.clone()),
            ..Default::default()
        },
        ResourceSpec {
            npu: Some(npu),
            ..Default::default()
        },
        ResourceSpec {
            network_bandwidth_bps: 1,
            ..Default::default()
        },
    ] {
        task.resources = resources;
        let err = dispatcher
            .dispatch_one_shot(task.clone())
            .await
            .unwrap_err();
        assert!(matches!(err, DispatchError::Placement(_)), "{err}");
    }

    let mut remote = make_remote_worker(0x42);
    remote.gpu = Some(gpu.clone());
    pool.upsert(remote);
    task.resources = ResourceSpec {
        gpu: Some(gpu),
        ..Default::default()
    };
    let err = dispatcher.dispatch_one_shot(task).await.unwrap_err();
    assert!(matches!(err, DispatchError::Placement(_)), "{err}");
}

/// A `TrustedExecutor` policy whose allowlist omits the local peer must refuse
/// execution with the stable `ENTANGLE-E0303` code — the integrity gate the
/// dispatcher previously dropped entirely.
#[tokio::test]
async fn trusted_executor_empty_allowlist_refused_e0303() {
    let keypair = IdentityKeyPair::generate();
    let dispatcher = empty_dispatcher(&keypair);

    let mut task = OneShotTask::with_defaults(nothing_plugin_id(&keypair), b"x".to_vec());
    task.integrity = IntegrityPolicy::TrustedExecutor { allowlist: vec![] };

    let err = dispatcher
        .dispatch_one_shot(task)
        .await
        .expect_err("empty allowlist must refuse the local peer");
    assert!(
        matches!(err, DispatchError::Runtime(_)),
        "expected Runtime(integrity), got: {err:?}"
    );
    assert!(
        err.to_string().contains("ENTANGLE-E0303"),
        "error must carry stable ENTANGLE-E0303 code; got: {err}"
    );
}

#[tokio::test]
async fn trusted_executor_without_remote_transport_refuses_local_fallback_e0303() {
    let keypair = IdentityKeyPair::generate();
    let dispatcher = empty_dispatcher(&keypair);
    let mut task = OneShotTask::with_defaults(nothing_plugin_id(&keypair), Vec::new());
    task.integrity = IntegrityPolicy::TrustedExecutor {
        allowlist: vec![make_remote_worker(0x42).peer_id],
    };

    let error = dispatcher.dispatch_one_shot(task).await.unwrap_err();
    assert!(matches!(
        error,
        DispatchError::Runtime(entangle_runtime::RuntimeError::Integrity(
            entangle_runtime::IntegrityError::TrustedExecutorRefused(peer)
        )) if peer == local_peer().to_hex()
    ));
}

/// `Attested` integrity is not implemented in Phase 1; the dispatcher must
/// surface the stable `ENTANGLE-E0304` NotImplemented error rather than execute.
#[tokio::test]
async fn attested_policy_returns_e0304_not_implemented() {
    let keypair = IdentityKeyPair::generate();
    let dispatcher = empty_dispatcher(&keypair);

    let mut task = OneShotTask::with_defaults(nothing_plugin_id(&keypair), b"x".to_vec());
    task.integrity = IntegrityPolicy::Attested { tee: "sgx".into() };

    let err = dispatcher
        .dispatch_one_shot(task)
        .await
        .expect_err("Attested must not execute in Phase 1");
    assert!(
        err.to_string().contains("ENTANGLE-E0304"),
        "error must carry stable ENTANGLE-E0304 code; got: {err}"
    );
}

/// An input larger than `max_input_bytes` is rejected up front, before any
/// placement or kernel invocation.
#[tokio::test]
async fn oversized_input_is_rejected() {
    let keypair = IdentityKeyPair::generate();
    let dispatcher = empty_dispatcher(&keypair);

    let mut task =
        OneShotTask::with_defaults(nothing_plugin_id(&keypair), b"way too long".to_vec());
    task.max_input_bytes = 3;

    let err = dispatcher
        .dispatch_one_shot(task)
        .await
        .expect_err("oversized input must be rejected");
    match err {
        DispatchError::InputSizeExceeded { declared, actual } => {
            assert_eq!(declared, 3);
            assert_eq!(actual, "way too long".len() as u64);
        }
        other => panic!("expected InputSizeExceeded, got: {other:?}"),
    }
}

/// An output larger than `max_output_bytes` is rejected with the canonical
/// `ENTANGLE-E0300` semantics. Uses the hello-pong fixture, which echoes
/// "Hello, <input>!".
#[tokio::test]
async fn oversized_output_is_rejected_e0300() {
    let wasm = hello_pong_wasm();

    let keypair = IdentityKeyPair::generate();
    let keyring = build_keyring(&keypair);
    let dir = tempfile::tempdir().expect("tempdir");
    let plugin_id_str = write_plugin_package(dir.path(), &keypair, &wasm);
    let plugin_id: entangle_types::plugin_id::PluginId =
        plugin_id_str.parse().expect("parse plugin id");

    let kernel = Arc::new(Kernel::new(KernelConfig::default(), keyring).expect("kernel"));
    kernel
        .load_plugin_from_dir(dir.path())
        .await
        .expect("load ok");

    let dispatcher = Dispatcher::new(WorkerPool::new(), kernel, local_peer());

    let mut task = OneShotTask::with_defaults(plugin_id, b"world".to_vec());
    task.max_output_bytes = 4; // "Hello, world!" (13 bytes) exceeds this.

    let err = dispatcher
        .dispatch_one_shot(task)
        .await
        .expect_err("oversized output must be rejected");
    assert!(
        matches!(err, DispatchError::OutputSizeExceeded(_)),
        "expected OutputSizeExceeded, got: {err:?}"
    );
    assert!(
        err.to_string().contains("ENTANGLE-E0300"),
        "error must carry stable ENTANGLE-E0300 code; got: {err}"
    );
}
