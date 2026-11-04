//! `[lifecycle]` (spec §3.3, §4.4): eager and lazy activation, idle teardown
//! and re-activation, streams keeping a plugin active, and the lifecycle
//! events each step publishes.

use entangle_observability::{catalog::names, Registry};
use entangle_runtime::{Kernel, KernelConfig, LifecyclePhase};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::plugin_id::PluginId;
use std::path::Path;
use std::time::Duration;

const HELLO: &[u8] = include_bytes!("../../entangle-host/tests/fixtures/hello-pong.wasm");
const STREAM_PROBE: &[u8] =
    include_bytes!("../../entangle-host/tests/fixtures/stream-caps-probe.wasm");

fn keyring_for(kp: &IdentityKeyPair) -> Keyring {
    let mut kr = Keyring::new();
    kr.add(TrustEntry {
        fingerprint: kp.fingerprint(),
        public_key: *kp.public().as_bytes(),
        publisher_name: "lifecycle".into(),
        added_at: 0,
        note: String::new(),
    });
    kr
}

/// A signed package `name@0.1.0` of `wasm` whose manifest ends with `extra`.
fn write_package(dir: &Path, kp: &IdentityKeyPair, name: &str, wasm: &[u8], extra: &str) -> String {
    std::fs::create_dir_all(dir).unwrap();
    let id = format!("{}/{name}@0.1.0", kp.fingerprint_hex());
    let manifest = format!(
        "[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = 1\nruntime = \"wasm\"\n\n{extra}"
    );
    std::fs::write(dir.join("entangle.toml"), &manifest).unwrap();
    std::fs::write(dir.join("plugin.wasm"), wasm).unwrap();
    std::fs::write(
        dir.join("plugin.wasm.sig"),
        toml::to_string(&sign_artifact(wasm, manifest.as_bytes(), kp)).unwrap(),
    )
    .unwrap();
    id
}

fn kernel(kp: &IdentityKeyPair, registry: &Registry) -> Kernel {
    Kernel::new(KernelConfig::default(), keyring_for(kp))
        .unwrap()
        .with_metrics(registry.clone())
}

/// Every phase published for `id` within `wait`.
async fn phases_for(
    sub: &mut entangle_ipc::bus::Subscriber<entangle_runtime::LifecycleEvent>,
    id: &PluginId,
    wait: Duration,
) -> Vec<LifecyclePhase> {
    let mut out = Vec::new();
    while let Ok(Ok(env)) = tokio::time::timeout(wait, sub.recv()).await {
        if env.payload.plugin == *id {
            out.push(env.payload.phase);
        }
    }
    out
}

/// Wait (bounded) for `phase` for `id`; the phases seen before it.
async fn until_phase(
    sub: &mut entangle_ipc::bus::Subscriber<entangle_runtime::LifecycleEvent>,
    id: &PluginId,
    phase: LifecyclePhase,
    within: Duration,
) -> Vec<LifecyclePhase> {
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let env = tokio::time::timeout(left, sub.recv())
            .await
            .unwrap_or_else(|_| panic!("no {phase:?} within {within:?}; saw {seen:?}"))
            .expect("bus open");
        if env.payload.plugin != *id {
            continue;
        }
        if env.payload.phase == phase {
            return seen;
        }
        seen.push(env.payload.phase);
    }
}

const QUIET: Duration = Duration::from_millis(150);

#[tokio::test(flavor = "multi_thread")]
async fn an_eager_plugin_is_instantiated_at_load() {
    let tmp = tempfile::tempdir().unwrap();
    let kp = IdentityKeyPair::generate();
    // No [lifecycle] table: eager, as every plugin was before it existed.
    write_package(tmp.path(), &kp, "eager", HELLO, "");
    let reg = Registry::new();
    let k = kernel(&kp, &reg);
    let mut sub = k.bus().subscribe();
    let id = k.load_plugin_from_dir(tmp.path()).await.unwrap();
    assert_eq!(k.is_instantiated(&id), Some(true));
    assert_eq!(
        phases_for(&mut sub, &id, QUIET).await,
        [
            LifecyclePhase::ManifestValidated,
            LifecyclePhase::SignatureVerified,
            LifecyclePhase::Registered,
            LifecyclePhase::Loaded,
        ]
    );
    assert_eq!(
        k.invoke(&id, b"eager", 10_000).await.unwrap(),
        b"Hello, eager!"
    );
    assert_eq!(
        phases_for(&mut sub, &id, QUIET).await,
        [LifecyclePhase::Activated, LifecyclePhase::Idled],
        "no on-demand instantiation for an eager plugin"
    );
    assert_eq!(k.is_instantiated(&id), Some(true));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lazy_plugin_is_verified_at_load_and_instantiated_on_first_call() {
    let tmp = tempfile::tempdir().unwrap();
    let kp = IdentityKeyPair::generate();
    write_package(
        tmp.path(),
        &kp,
        "lazy",
        HELLO,
        "[lifecycle]\nactivation = \"lazy\"\n",
    );
    let reg = Registry::new();
    let k = kernel(&kp, &reg);
    let mut sub = k.bus().subscribe();
    let id = k.load_plugin_from_dir(tmp.path()).await.unwrap();
    assert_eq!(k.plugin_world(&id), Some("plugin"), "checked at load");
    assert_eq!(k.is_instantiated(&id), Some(false));
    assert_eq!(
        k.loaded_source(&id).unwrap().lifecycle.activation,
        entangle_runtime::Activation::Lazy
    );
    assert_eq!(
        phases_for(&mut sub, &id, QUIET).await,
        [
            LifecyclePhase::ManifestValidated,
            LifecyclePhase::SignatureVerified,
            LifecyclePhase::Registered,
            LifecyclePhase::Loaded,
        ]
    );

    assert_eq!(k.invoke(&id, b"", 10_000).await.unwrap(), b"pong");
    assert_eq!(k.is_instantiated(&id), Some(true));
    assert_eq!(
        phases_for(&mut sub, &id, QUIET).await,
        [
            LifecyclePhase::Instantiated,
            LifecyclePhase::Activated,
            LifecyclePhase::Idled
        ]
    );
    // Later calls reuse the instance.
    assert_eq!(k.invoke(&id, b"two", 10_000).await.unwrap(), b"Hello, two!");
    assert_eq!(
        phases_for(&mut sub, &id, QUIET).await,
        [LifecyclePhase::Activated, LifecyclePhase::Idled]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_first_calls_create_one_instance() {
    let tmp = tempfile::tempdir().unwrap();
    let kp = IdentityKeyPair::generate();
    write_package(
        tmp.path(),
        &kp,
        "lazy",
        HELLO,
        "[lifecycle]\nactivation = \"lazy\"\n",
    );
    let reg = Registry::new();
    let k = std::sync::Arc::new(kernel(&kp, &reg));
    let id = k.load_plugin_from_dir(tmp.path()).await.unwrap();
    let mut sub = k.bus().subscribe();
    let calls: Vec<_> = (0..4)
        .map(|_| {
            let (k, id) = (k.clone(), id.clone());
            tokio::spawn(async move { k.invoke(&id, b"", 10_000).await })
        })
        .collect();
    for c in calls {
        assert_eq!(c.await.unwrap().unwrap(), b"pong");
    }
    let phases = phases_for(&mut sub, &id, QUIET).await;
    assert_eq!(
        phases
            .iter()
            .filter(|p| **p == LifecyclePhase::Instantiated)
            .count(),
        1,
        "{phases:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_idle_instance_is_torn_down_and_reactivated_on_the_next_call() {
    let tmp = tempfile::tempdir().unwrap();
    let kp = IdentityKeyPair::generate();
    write_package(
        tmp.path(),
        &kp,
        "idle",
        HELLO,
        "[lifecycle]\nidle-timeout-secs = 1\n",
    );
    let reg = Registry::new();
    let k = kernel(&kp, &reg);
    let mut sub = k.bus().subscribe();
    let id = k.load_plugin_from_dir(tmp.path()).await.unwrap();
    assert_eq!(k.is_instantiated(&id), Some(true), "eager, with a timeout");
    assert_eq!(k.invoke(&id, b"a", 10_000).await.unwrap(), b"Hello, a!");

    let before = until_phase(
        &mut sub,
        &id,
        LifecyclePhase::TornDown,
        Duration::from_secs(10),
    )
    .await;
    assert!(
        before.ends_with(&[LifecyclePhase::Activated, LifecyclePhase::Idled]),
        "{before:?}"
    );
    assert_eq!(k.is_instantiated(&id), Some(false));
    assert_eq!(k.list_plugins(), vec![id.clone()], "still loaded");
    assert_eq!(
        reg.value(names::PLUGIN_IDLE_TEARDOWNS, &[("plugin", &id.to_string())]),
        Some(1.0)
    );

    // The next call brings it back.
    assert_eq!(k.invoke(&id, b"b", 10_000).await.unwrap(), b"Hello, b!");
    assert_eq!(k.is_instantiated(&id), Some(true));
    let again = until_phase(&mut sub, &id, LifecyclePhase::Idled, Duration::from_secs(5)).await;
    assert_eq!(
        again,
        [LifecyclePhase::Instantiated, LifecyclePhase::Activated]
    );
    // And it idles out again.
    until_phase(
        &mut sub,
        &id,
        LifecyclePhase::TornDown,
        Duration::from_secs(10),
    )
    .await;
    assert_eq!(
        reg.value(names::PLUGIN_IDLE_TEARDOWNS, &[("plugin", &id.to_string())]),
        Some(2.0)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn calls_keep_a_plugin_from_idling_out() {
    let tmp = tempfile::tempdir().unwrap();
    let kp = IdentityKeyPair::generate();
    write_package(
        tmp.path(),
        &kp,
        "busy",
        HELLO,
        "[lifecycle]\nactivation = \"lazy\"\nidle-timeout-secs = 1\n",
    );
    let reg = Registry::new();
    let k = kernel(&kp, &reg);
    let id = k.load_plugin_from_dir(tmp.path()).await.unwrap();
    // A call every 300 ms for 2.4 s: never idle for a whole second.
    for _ in 0..8 {
        assert_eq!(k.invoke(&id, b"", 10_000).await.unwrap(), b"pong");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(k.is_instantiated(&id), Some(true));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_in_progress_keeps_the_plugin_active() {
    let tmp = tempfile::tempdir().unwrap();
    let kp = IdentityKeyPair::generate();
    write_package(
        tmp.path(),
        &kp,
        "streamer",
        STREAM_PROBE,
        "[lifecycle]\nactivation = \"lazy\"\nidle-timeout-secs = 1\n",
    );
    let reg = Registry::new();
    let k = std::sync::Arc::new(kernel(&kp, &reg));
    let mut sub = k.bus().subscribe();
    let id = k.load_plugin_from_dir(tmp.path()).await.unwrap();
    assert_eq!(k.plugin_world(&id), Some("stream-plugin"));
    assert_eq!(k.is_instantiated(&id), Some(false));

    let (port, mut driver) = entangle_host::stream_port(1);
    let (kk, pid) = (k.clone(), id.clone());
    let stream = tokio::spawn(async move { kk.invoke_stream(&pid, b"ls /\n", port, 30_000).await });
    let chunk = driver.chunks.recv().await.expect("first chunk");
    chunk.ack.sent();

    // Open for 2.5 s — longer than the idle timeout.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    assert_eq!(k.is_instantiated(&id), Some(true), "active while streaming");
    driver
        .input
        .send(entangle_host::StreamInput::Chunk(b"ls /\n".to_vec()))
        .await
        .unwrap();
    let chunk = driver.chunks.recv().await.expect("still streaming");
    chunk.ack.sent();
    driver
        .input
        .send(entangle_host::StreamInput::End)
        .await
        .unwrap();
    stream.await.unwrap().expect("the stream completes");

    let seen = until_phase(
        &mut sub,
        &id,
        LifecyclePhase::TornDown,
        Duration::from_secs(10),
    )
    .await;
    assert!(
        !seen.contains(&LifecyclePhase::TornDown),
        "not torn down during the stream: {seen:?}"
    );
    assert!(
        seen.ends_with(&[
            LifecyclePhase::Instantiated,
            LifecyclePhase::Activated,
            LifecyclePhase::Idled
        ]),
        "{seen:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unloaded_plugin_is_not_torn_down_after_its_unload() {
    let tmp = tempfile::tempdir().unwrap();
    let kp = IdentityKeyPair::generate();
    write_package(
        tmp.path(),
        &kp,
        "gone",
        HELLO,
        "[lifecycle]\nidle-timeout-secs = 1\n",
    );
    let reg = Registry::new();
    let k = kernel(&kp, &reg);
    let id = k.load_plugin_from_dir(tmp.path()).await.unwrap();
    let mut sub = k.bus().subscribe();
    k.unload(&id).await.unwrap();
    let phases = phases_for(&mut sub, &id, Duration::from_millis(1_800)).await;
    assert_eq!(phases, [LifecyclePhase::Unloaded]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bad_lifecycle_table_fails_the_load() {
    let tmp = tempfile::tempdir().unwrap();
    let kp = IdentityKeyPair::generate();
    write_package(
        tmp.path(),
        &kp,
        "bad",
        HELLO,
        "[lifecycle]\nidle-timeout-secs = 0\n",
    );
    let reg = Registry::new();
    let k = kernel(&kp, &reg);
    let err = k.load_plugin_from_dir(tmp.path()).await.unwrap_err();
    assert!(err.to_string().contains("ENTANGLE-E0780"), "{err}");
    assert!(k.list_plugins().is_empty());
}
