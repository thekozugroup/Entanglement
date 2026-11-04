//! Hot reload (spec §3.1, §3.3, §4.4.1 case B): loading another version of a
//! loaded plugin swaps it — calls and streams in flight finish on the old
//! version, new ones (also when addressed to the old id) run on the new one,
//! the old one drains and unloads — after the new version's `migrate` hook,
//! if it has one. More authority, or a lower version, needs explicit consent.

use entangle_observability::{catalog::names, Registry};
use entangle_runtime::{
    Kernel, KernelConfig, LifecyclePhase, LoadOptions, NativeConfig, RuntimeError,
};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::plugin_id::PluginId;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const PROBE: &[u8] = include_bytes!("../../entangle-host/tests/fixtures/lifecycle-probe.wasm");
const HELLO: &[u8] = include_bytes!("../../entangle-host/tests/fixtures/hello-pong.wasm");
const STREAM_PROBE: &[u8] =
    include_bytes!("../../entangle-host/tests/fixtures/stream-caps-probe.wasm");

struct Fixture {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    kp: IdentityKeyPair,
    registry: Registry,
    kernel: Arc<Kernel>,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let kp = IdentityKeyPair::generate();
        let mut kr = Keyring::new();
        kr.add(TrustEntry {
            fingerprint: kp.fingerprint(),
            public_key: *kp.public().as_bytes(),
            publisher_name: "hot-reload".into(),
            added_at: 0,
            note: String::new(),
        });
        let registry = Registry::new();
        let kernel = Arc::new(
            Kernel::new(
                KernelConfig {
                    native: NativeConfig {
                        data_dir: Some(root.join("data")),
                        ..NativeConfig::default()
                    },
                    // Versions sharing a component deserialize instead of
                    // recompiling, as on a daemon.
                    aot_cache: Some(entangle_runtime::AotCacheConfig::new(root.join("aot"))),
                    ..KernelConfig::default()
                },
                kr,
            )
            .unwrap()
            .with_metrics(registry.clone()),
        );
        Self {
            _tmp: tmp,
            root,
            kp,
            registry,
            kernel,
        }
    }

    /// A signed package of `name@version` (tier `tier`, `[capabilities]`
    /// `caps`) in its own directory.
    fn package(&self, name: &str, version: &str, wasm: &[u8], tier: u8, caps: &str) -> PathBuf {
        let dir = self.root.join(format!("{name}-{version}"));
        std::fs::create_dir_all(&dir).unwrap();
        let id = format!("{}/{name}@{version}", self.kp.fingerprint_hex());
        let manifest = format!(
            "[plugin]\nid = \"{id}\"\nversion = \"{version}\"\ntier = {tier}\nruntime = \"wasm\"\n\n\
             [capabilities]\n{caps}\n"
        );
        std::fs::write(dir.join("entangle.toml"), &manifest).unwrap();
        std::fs::write(dir.join("plugin.wasm"), wasm).unwrap();
        std::fs::write(
            dir.join("plugin.wasm.sig"),
            toml::to_string(&sign_artifact(wasm, manifest.as_bytes(), &self.kp)).unwrap(),
        )
        .unwrap();
        dir
    }

    fn id(&self, name: &str, version: &str) -> PluginId {
        format!("{}/{name}@{version}", self.kp.fingerprint_hex())
            .parse()
            .unwrap()
    }

    async fn call(&self, id: &PluginId, input: &str) -> String {
        String::from_utf8(
            self.kernel
                .invoke(id, input.as_bytes(), 30_000)
                .await
                .unwrap(),
        )
        .unwrap()
    }

    fn reloads(&self, outcome: &str) -> f64 {
        self.registry
            .value(names::PLUGIN_RELOADS, &[("outcome", outcome)])
            .unwrap_or(0.0)
    }
}

async fn drained(mut rx: tokio::sync::watch::Receiver<bool>) {
    tokio::time::timeout(Duration::from_secs(30), rx.wait_for(|d| *d))
        .await
        .expect("drained within 30 s")
        .expect("drain task alive");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_in_flight_finishes_on_the_old_version_and_the_next_sees_the_new() {
    let f = Fixture::new();
    let (v1, v2) = (f.id("probe", "0.1.0"), f.id("probe", "0.2.0"));
    f.kernel
        .load_plugin_from_dir(&f.package("probe", "0.1.0", PROBE, 1, ""))
        .await
        .unwrap();
    assert_eq!(f.call(&v1, "id").await, v1.to_string());

    let mut sub = f.kernel.bus().subscribe();
    // A slow call on 0.1.0.
    let (k, id) = (f.kernel.clone(), v1.clone());
    let slow = tokio::spawn(async move { k.invoke(&id, b"spin:10000", 60_000).await });
    loop {
        let env = sub.recv().await.unwrap();
        if env.payload.plugin == v1 && env.payload.phase == LifecyclePhase::Activated {
            break;
        }
    }

    let outcome = f
        .kernel
        .load_plugin(
            &f.package("probe", "0.2.0", PROBE, 1, ""),
            LoadOptions::default(),
        )
        .await
        .expect("an upgrade with the same capabilities needs no consent");
    assert_eq!(outcome.plugin_id, v2);
    let replaced = outcome.replaced.expect("a hot reload");
    assert_eq!(replaced.previous, v1);
    assert!(replaced.migrated, "lifecycle-probe exports migrate");
    assert_eq!(f.kernel.list_plugins(), vec![v2.clone()]);
    assert!(
        !*replaced.drained.borrow(),
        "the slow call is still running"
    );

    // New calls — also addressed to the old id — run on 0.2.0 at once.
    assert_eq!(f.call(&v2, "x").await, format!("{v2}|x"));
    assert_eq!(f.call(&v1, "y").await, format!("{v2}|y"));

    // The slow call completes on 0.1.0.
    let out = slow.await.unwrap().expect("the in-flight call completes");
    assert_eq!(String::from_utf8(out).unwrap(), format!("{v1} spun"));
    drained(replaced.drained).await;
    assert_eq!(
        f.kernel.broker().registered_tiers().len(),
        1,
        "0.1.0 released"
    );
    assert_eq!(f.reloads("swapped"), 1.0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_on_the_old_version_drains_while_new_streams_use_the_new() {
    let f = Fixture::new();
    let v1 = f.id("streamer", "1.0.0");
    f.kernel
        .load_plugin_from_dir(&f.package("streamer", "1.0.0", STREAM_PROBE, 1, ""))
        .await
        .unwrap();
    let mut sub = f.kernel.bus().subscribe();

    let (port, mut driver) = entangle_host::stream_port(1);
    let (k, id) = (f.kernel.clone(), v1.clone());
    let old_stream =
        tokio::spawn(async move { k.invoke_stream(&id, b"ls /\n", port, 30_000).await });
    driver.chunks.recv().await.expect("first chunk").ack.sent();

    let outcome = f
        .kernel
        .load_plugin(
            &f.package("streamer", "1.1.0", STREAM_PROBE, 1, ""),
            LoadOptions::default(),
        )
        .await
        .expect("the swap does not wait for the stream");
    let replaced = outcome.replaced.expect("a hot reload");
    assert!(!replaced.migrated, "stream-caps-probe has no migrate hook");

    // The old stream still carries chunks.
    driver
        .input
        .send(entangle_host::StreamInput::Chunk(b"ls /\n".to_vec()))
        .await
        .unwrap();
    driver
        .chunks
        .recv()
        .await
        .expect("old stream alive")
        .ack
        .sent();
    assert!(!*replaced.drained.borrow());

    // A new stream, addressed to the old id, runs on 1.1.0.
    let (port2, mut driver2) = entangle_host::stream_port(1);
    let (k, id) = (f.kernel.clone(), v1.clone());
    let new_stream =
        tokio::spawn(async move { k.invoke_stream(&id, b"ls /\n", port2, 30_000).await });
    driver2.chunks.recv().await.expect("new stream").ack.sent();
    driver2
        .input
        .send(entangle_host::StreamInput::End)
        .await
        .unwrap();
    new_stream.await.unwrap().expect("new stream completes");

    driver
        .input
        .send(entangle_host::StreamInput::End)
        .await
        .unwrap();
    old_stream.await.unwrap().expect("old stream completes");
    drained(replaced.drained).await;

    // Event order: 1.1.0 loaded while 1.0.0's stream ran; 1.0.0 unloaded only
    // after its stream ended; the second stream was 1.1.0's.
    let mut seen = Vec::new();
    while let Ok(Ok(env)) = tokio::time::timeout(Duration::from_millis(200), sub.recv()).await {
        seen.push((env.payload.plugin.version.to_string(), env.payload.phase));
    }
    let pos = |v: &str, p: LifecyclePhase| {
        seen.iter()
            .position(|(sv, sp)| sv == v && *sp == p)
            .unwrap_or_else(|| panic!("{v} {p:?} in {seen:?}"))
    };
    assert!(pos("1.1.0", LifecyclePhase::Loaded) < pos("1.0.0", LifecyclePhase::Idled));
    assert!(pos("1.0.0", LifecyclePhase::Idled) < pos("1.0.0", LifecyclePhase::Unloaded));
    assert!(pos("1.1.0", LifecyclePhase::Activated) > pos("1.1.0", LifecyclePhase::Loaded));
}

#[tokio::test(flavor = "multi_thread")]
async fn more_capabilities_or_a_higher_tier_need_consent() {
    let f = Fixture::new();
    let (v1, v2) = (f.id("probe", "0.1.0"), f.id("probe", "0.2.0"));
    f.kernel
        .load_plugin_from_dir(&f.package("probe", "0.1.0", PROBE, 1, "\"custom.telemetry\" = {}"))
        .await
        .unwrap();
    let wider = f.package(
        "probe",
        "0.2.0",
        PROBE,
        3,
        "\"custom.telemetry\" = {}\n\"net.wan\" = { hosts = [\"api.example.com:443\"] }",
    );
    let err = f
        .kernel
        .load_plugin(&wider, LoadOptions::default())
        .await
        .unwrap_err();
    let RuntimeError::ReloadNeedsConsent(consent) = &err else {
        panic!("{err}");
    };
    assert_eq!((&consent.from, &consent.to), (&v1, &v2));
    assert_eq!(
        consent.diff.added,
        vec!["net.wan (hosts=api.example.com:443)"]
    );
    assert!(consent.diff.removed.is_empty());
    let text = err.to_string();
    assert!(text.starts_with("ENTANGLE-E0781"), "{text}");
    assert!(text.contains("--accept-new-capabilities"), "{text}");
    assert!(
        text.contains("+ net.wan (hosts=api.example.com:443)"),
        "{text}"
    );
    assert!(text.contains("tier 1 -> 3"), "{text}");
    // Nothing changed.
    assert_eq!(f.kernel.list_plugins(), vec![v1.clone()]);
    assert_eq!(f.kernel.broker().registered_tiers().len(), 1);
    assert_eq!(f.call(&v1, "id").await, v1.to_string());
    assert_eq!(f.reloads("refused"), 1.0);

    // With consent it swaps.
    let outcome = f
        .kernel
        .load_plugin(
            &wider,
            LoadOptions {
                accept_new_capabilities: true,
                ..LoadOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(outcome.plugin_id, v2);
    drained(outcome.replaced.unwrap().drained).await;

    // Dropping a capability (and the tier) needs none.
    let narrower = f.package("probe", "0.3.0", PROBE, 1, "\"custom.telemetry\" = {}");
    let outcome = f
        .kernel
        .load_plugin(&narrower, LoadOptions::default())
        .await
        .expect("less authority needs no consent");
    assert_eq!(outcome.plugin_id, f.id("probe", "0.3.0"));
}

/// Escalation by tier alone: the capabilities are identical, only the tier
/// rises, so the diff has nothing added and the tier is what needs consent.
#[tokio::test(flavor = "multi_thread")]
async fn a_higher_tier_alone_needs_consent() {
    let f = Fixture::new();
    let (v1, v2) = (f.id("probe", "0.1.0"), f.id("probe", "0.2.0"));
    let caps = "\"custom.telemetry\" = {}";
    f.kernel
        .load_plugin_from_dir(&f.package("probe", "0.1.0", PROBE, 1, caps))
        .await
        .unwrap();
    let higher = f.package("probe", "0.2.0", PROBE, 3, caps);
    let err = f
        .kernel
        .load_plugin(&higher, LoadOptions::default())
        .await
        .unwrap_err();
    let RuntimeError::ReloadNeedsConsent(consent) = &err else {
        panic!("{err}");
    };
    assert_eq!((&consent.from, &consent.to), (&v1, &v2));
    assert!(consent.diff.added.is_empty(), "{:?}", consent.diff);
    assert!(consent.diff.removed.is_empty(), "{:?}", consent.diff);
    assert!(
        consent.diff.tier.1 > consent.diff.tier.0,
        "{:?}",
        consent.diff.tier
    );
    assert!(err.to_string().starts_with("ENTANGLE-E0781"), "{err}");
    assert_eq!(f.kernel.list_plugins(), vec![v1.clone()]);

    let outcome = f
        .kernel
        .load_plugin(
            &higher,
            LoadOptions {
                accept_new_capabilities: true,
                ..LoadOptions::default()
            },
        )
        .await
        .expect("consent admits the higher tier");
    assert_eq!(outcome.plugin_id, v2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_downgrade_needs_its_own_flag() {
    let f = Fixture::new();
    f.kernel
        .load_plugin_from_dir(&f.package("probe", "0.2.0", PROBE, 1, ""))
        .await
        .unwrap();
    let older = f.package("probe", "0.1.0", PROBE, 1, "");
    let err = f
        .kernel
        .load_plugin(&older, LoadOptions::default())
        .await
        .unwrap_err();
    assert!(matches!(err, RuntimeError::ReloadDowngrade { .. }), "{err}");
    assert!(err.to_string().contains("--allow-downgrade"), "{err}");
    let err = f
        .kernel
        .load_plugin(
            &older,
            LoadOptions {
                accept_new_capabilities: true,
                ..LoadOptions::default()
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, RuntimeError::ReloadDowngrade { .. }), "{err}");
    let outcome = f
        .kernel
        .load_plugin(
            &older,
            LoadOptions {
                allow_downgrade: true,
                ..LoadOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(outcome.plugin_id, f.id("probe", "0.1.0"));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_migrate_hook_runs_on_the_new_version_with_its_grants() {
    let f = Fixture::new();
    let caps = "\"storage.local\" = { mode = \"rw\" }";
    let (v1, v2) = (f.id("probe", "0.1.0"), f.id("probe", "0.2.0"));
    f.kernel
        .load_plugin_from_dir(&f.package("probe", "0.1.0", PROBE, 1, caps))
        .await
        .unwrap();
    let mut sub = f.kernel.bus().subscribe();
    let outcome = f
        .kernel
        .load_plugin(
            &f.package("probe", "0.2.0", PROBE, 1, caps),
            LoadOptions::default(),
        )
        .await
        .unwrap();
    assert!(outcome.replaced.as_ref().unwrap().migrated);
    // It wrote into the plugin's storage, which both versions share.
    let data = f
        .root
        .join("data/plugins")
        .join(&v1.publisher)
        .join(&v1.name)
        .join("migrated");
    assert_eq!(std::fs::read_to_string(data).unwrap(), "0.1.0->0.2.0");
    assert_eq!(f.call(&v2, "read /data/migrated").await, "0.1.0->0.2.0");
    // `Migrated` is published for the new version before it is `Loaded`.
    let mut phases = Vec::new();
    while let Ok(Ok(env)) = tokio::time::timeout(Duration::from_millis(200), sub.recv()).await {
        if env.payload.plugin == v2 {
            phases.push(env.payload.phase);
        }
    }
    let at = |p| phases.iter().position(|x| *x == p).unwrap();
    assert!(
        at(LifecyclePhase::Migrated) < at(LifecyclePhase::Loaded),
        "{phases:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failing_migrate_hook_keeps_the_old_version() {
    let f = Fixture::new();
    let v1 = f.id("probe", "0.1.0");
    f.kernel
        .load_plugin_from_dir(&f.package("probe", "0.1.0", PROBE, 1, ""))
        .await
        .unwrap();
    // lifecycle-probe's hook refuses in a version tagged `fail`.
    let err = f
        .kernel
        .load_plugin(
            &f.package("probe", "0.3.0-fail", PROBE, 1, ""),
            LoadOptions::default(),
        )
        .await
        .unwrap_err();
    let RuntimeError::MigrateFailed { from, message, .. } = &err else {
        panic!("{err}");
    };
    assert_eq!(**from, v1);
    assert!(
        message.contains("refuses to migrate from 0.1.0"),
        "{message}"
    );
    assert!(err.to_string().starts_with("ENTANGLE-E0783"), "{err}");
    assert_eq!(f.kernel.list_plugins(), vec![v1.clone()]);
    assert_eq!(
        f.kernel.broker().registered_tiers().len(),
        1,
        "0.3.0 rolled back"
    );
    assert_eq!(f.call(&v1, "id").await, v1.to_string());
    assert_eq!(f.reloads("migrate_failed"), 1.0);
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_migrate_hook_it_is_drain_and_swap() {
    let f = Fixture::new();
    let (v1, v2) = (f.id("hello", "0.1.0"), f.id("hello", "0.2.0"));
    f.kernel
        .load_plugin_from_dir(&f.package("hello", "0.1.0", HELLO, 1, ""))
        .await
        .unwrap();
    let outcome = f
        .kernel
        .load_plugin(
            &f.package("hello", "0.2.0", HELLO, 1, ""),
            LoadOptions::default(),
        )
        .await
        .unwrap();
    let replaced = outcome.replaced.unwrap();
    assert!(!replaced.migrated);
    drained(replaced.drained).await;
    assert_eq!(f.call(&v2, "x").await, "Hello, x!");

    // The same version again is still refused, and unloading the current
    // version ends the old id's forwarding too.
    let err = f
        .kernel
        .load_plugin_from_dir(&f.root.join("hello-0.2.0"))
        .await
        .unwrap_err();
    assert!(matches!(err, RuntimeError::AlreadyLoaded(_)), "{err}");
    f.kernel.unload(&v2).await.unwrap();
    let err = f.kernel.invoke(&v1, b"", 10_000).await.unwrap_err();
    assert!(matches!(err, RuntimeError::NotLoaded(_)), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn chained_reloads_forward_every_old_id_to_the_newest() {
    let f = Fixture::new();
    for v in ["0.1.0", "0.2.0", "0.3.0"] {
        let outcome = f
            .kernel
            .load_plugin(&f.package("probe", v, PROBE, 1, ""), LoadOptions::default())
            .await
            .unwrap();
        if let Some(r) = outcome.replaced {
            drained(r.drained).await;
        }
    }
    let newest = f.id("probe", "0.3.0");
    for v in ["0.1.0", "0.2.0", "0.3.0"] {
        assert_eq!(f.call(&f.id("probe", v), "id").await, newest.to_string());
    }
    assert_eq!(f.kernel.broker().registered_tiers().len(), 1);
}

/// Two new versions loaded at once over the same plugin: never two versions
/// loaded, never a swap checked against a version that is no longer there.
/// Each load either swaps or is refused (`ENTANGLE-E0789`, or `ENTANGLE-E0782`
/// when it is checked against the winner and is older).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_reloads_leave_exactly_one_version() {
    let f = Fixture::new();
    f.kernel
        .load_plugin_from_dir(&f.package("probe", "0.1.0", PROBE, 1, ""))
        .await
        .unwrap();
    let (a, b) = (
        f.package("probe", "0.2.0", PROBE, 1, ""),
        f.package("probe", "0.3.0", PROBE, 1, ""),
    );
    let (ka, kb) = (f.kernel.clone(), f.kernel.clone());
    let (ra, rb) = tokio::join!(
        tokio::spawn(async move { ka.load_plugin(&a, LoadOptions::default()).await }),
        tokio::spawn(async move { kb.load_plugin(&b, LoadOptions::default()).await }),
    );
    for r in [ra.unwrap(), rb.unwrap()] {
        match r {
            Ok(o) => {
                if let Some(r) = o.replaced {
                    drained(r.drained).await;
                }
            }
            // Reloads are serialised per plugin, so the loser is checked against
            // the winner: 0.2.0 after 0.3.0 is a downgrade (E0782); the race
            // refusal (E0789) stays acceptable too.
            Err(e) => assert!(
                matches!(
                    e,
                    RuntimeError::ReloadRaced(_) | RuntimeError::ReloadDowngrade { .. }
                ) && (e.to_string().starts_with("ENTANGLE-E0789")
                    || e.to_string().starts_with("ENTANGLE-E0782")),
                "{e}"
            ),
        }
    }
    let loaded = f.kernel.list_plugins();
    assert_eq!(loaded.len(), 1, "{loaded:?}");
    assert_eq!(
        f.kernel.broker().registered_tiers().len(),
        1,
        "the refused version was rolled back"
    );
    let current = loaded[0].clone();
    assert_eq!(
        f.call(&f.id("probe", "0.1.0"), "id").await,
        current.to_string()
    );
}

/// Every check that a plugin is loaded honours the old id's forwarding, not
/// only `invoke`: the mesh stream server and the spot-check selection ask
/// [`Kernel::plugin_world`], `compute/dispatch` asks [`Kernel::resolve`].
#[tokio::test(flavor = "multi_thread")]
async fn an_old_id_is_loaded_for_every_check_after_a_reload() {
    let f = Fixture::new();
    let (v1, v2) = (f.id("probe", "0.1.0"), f.id("probe", "0.2.0"));
    f.kernel
        .load_plugin_from_dir(&f.package("probe", "0.1.0", PROBE, 1, ""))
        .await
        .unwrap();
    let outcome = f
        .kernel
        .load_plugin(
            &f.package("probe", "0.2.0", PROBE, 1, ""),
            LoadOptions::default(),
        )
        .await
        .unwrap();
    drained(outcome.replaced.unwrap().drained).await;
    assert_eq!(f.call(&v1, "id").await, v2.to_string());
    assert_eq!(f.kernel.plugin_world(&v1), Some("plugin"));
    assert_eq!(f.kernel.plugin_world(&v2), Some("plugin"));
    assert_eq!(f.kernel.resolve(&v1), Some(v2.clone()));
    assert_eq!(f.kernel.resolve(&v2), Some(v2.clone()));
    assert_eq!(f.kernel.resolve(&f.id("probe", "0.9.0")), None);

    // Unloading the version answering ends it everywhere.
    f.kernel.unload(&v2).await.unwrap();
    assert_eq!(f.kernel.plugin_world(&v1), None);
    assert_eq!(f.kernel.resolve(&v1), None);
}

/// Revoking a capability from a replaced version's id withdraws it where
/// calls to that id run now — the new version — and from the replaced
/// version's calls and streams still draining, instead of only from the
/// draining registration while every new call through the id keeps it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoking_through_a_replaced_id_reaches_the_version_answering_for_it() {
    use entangle_broker::GrantState;
    let f = Fixture::new();
    let caps = "\"storage.local\" = { mode = \"rw\" }";
    let (v1, v2) = (f.id("streamer", "1.0.0"), f.id("streamer", "1.1.0"));
    f.kernel
        .load_plugin_from_dir(&f.package("streamer", "1.0.0", STREAM_PROBE, 1, caps))
        .await
        .unwrap();
    // A stream on 1.0.0 keeps it draining after the reload.
    let (port, mut old) = entangle_host::stream_port(1);
    let (k, id) = (f.kernel.clone(), v1.clone());
    let old_stream =
        tokio::spawn(async move { k.invoke_stream(&id, b"ls /\n", port, 30_000).await });
    old.chunks.recv().await.expect("first chunk").ack.sent();
    let outcome = f
        .kernel
        .load_plugin(
            &f.package("streamer", "1.1.0", STREAM_PROBE, 1, caps),
            LoadOptions::default(),
        )
        .await
        .unwrap();
    let replaced = outcome.replaced.unwrap();

    f.kernel
        .revoke_capability(&v1, "storage.local")
        .expect("revoking through the replaced id");
    let state = |id: &PluginId| {
        f.kernel
            .capability_report(id)
            .unwrap()
            .into_iter()
            .find(|s| s.capability.key() == "storage.local")
            .unwrap()
            .state
    };
    assert_eq!(
        state(&v2),
        GrantState::Revoked,
        "the version answering for 1.0.0"
    );

    // A new stream addressed to the old id runs on 1.1.0, without it.
    let (port, mut new) = entangle_host::stream_port(1);
    let (k, id) = (f.kernel.clone(), v1.clone());
    let new_stream = tokio::spawn(async move {
        k.invoke_stream(&id, b"fetch storage-local\n", port, 30_000)
            .await
    });
    let chunk = new.chunks.recv().await.expect("new stream chunk");
    assert_eq!(String::from_utf8_lossy(&chunk.bytes), "err:revoked:");
    chunk.ack.sent();
    new.input
        .send(entangle_host::StreamInput::End)
        .await
        .unwrap();
    new_stream.await.unwrap().unwrap();

    // The draining stream on 1.0.0 lost it too.
    old.input
        .send(entangle_host::StreamInput::Chunk(
            b"fetch storage-local\n".to_vec(),
        ))
        .await
        .unwrap();
    let chunk = old.chunks.recv().await.expect("old stream chunk");
    assert_eq!(String::from_utf8_lossy(&chunk.bytes), "err:revoked:");
    chunk.ack.sent();
    old.input
        .send(entangle_host::StreamInput::End)
        .await
        .unwrap();
    old_stream.await.unwrap().unwrap();
    drained(replaced.drained).await;

    // Once 1.0.0 is gone, its id still reaches 1.1.0.
    f.kernel
        .revoke_capability(&v1, "storage.local")
        .expect("revoking through the replaced id after the drain");
}

/// Rolling back to the replaced version while it still drains (a stream on
/// it runs on) is refused with an error that says so — not the broker's
/// "already registered" for an id `plugins list` no longer shows — and works
/// once the drain is over.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rolling_back_to_a_draining_version_says_it_is_draining() {
    let f = Fixture::new();
    let (v1, v2) = (f.id("streamer", "1.0.0"), f.id("streamer", "1.1.0"));
    let old_dir = f.package("streamer", "1.0.0", STREAM_PROBE, 1, "");
    f.kernel.load_plugin_from_dir(&old_dir).await.unwrap();
    let (port, mut old) = entangle_host::stream_port(1);
    let (k, id) = (f.kernel.clone(), v1.clone());
    let old_stream =
        tokio::spawn(async move { k.invoke_stream(&id, b"ls /\n", port, 30_000).await });
    old.chunks.recv().await.expect("first chunk").ack.sent();
    let outcome = f
        .kernel
        .load_plugin(
            &f.package("streamer", "1.1.0", STREAM_PROBE, 1, ""),
            LoadOptions::default(),
        )
        .await
        .unwrap();
    let replaced = outcome.replaced.unwrap();

    let back = LoadOptions {
        allow_downgrade: true,
        ..LoadOptions::default()
    };
    let err = f.kernel.load_plugin(&old_dir, back).await.unwrap_err();
    assert!(matches!(err, RuntimeError::StillDraining(_)), "{err}");
    let text = err.to_string();
    assert!(text.starts_with("ENTANGLE-E0790"), "{text}");
    assert!(text.contains("still draining"), "{text}");
    assert!(text.contains(&v1.to_string()), "{text}");
    assert!(!text.contains("E0123"), "{text}");
    assert_eq!(f.kernel.list_plugins(), vec![f.id("streamer", "1.1.0")]);

    old.input
        .send(entangle_host::StreamInput::End)
        .await
        .unwrap();
    old_stream.await.unwrap().unwrap();
    drained(replaced.drained).await;
    let outcome = f.kernel.load_plugin(&old_dir, back).await.unwrap();
    assert_eq!(outcome.plugin_id, v1);
}

/// The migrate hook converts storage both versions share, which cannot be
/// undone: it may run only for a version that then goes live, migrating
/// from the version it actually replaces. Two reloads of one plugin at once
/// are serialised — the second is checked against, and migrates from, the
/// version the first installed (or is refused before its hook).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_reloads_migrate_only_for_the_version_that_goes_live() {
    for _ in 0..4 {
        let f = Fixture::new();
        let caps = "\"storage.local\" = { mode = \"rw\" }";
        let v1 = f.id("probe", "0.1.0");
        f.kernel
            .load_plugin_from_dir(&f.package("probe", "0.1.0", PROBE, 1, caps))
            .await
            .unwrap();
        let mut sub = f.kernel.bus().subscribe();
        let (a, b) = (
            f.package("probe", "0.2.0", PROBE, 1, caps),
            f.package("probe", "0.3.0", PROBE, 1, caps),
        );
        let (ka, kb) = (f.kernel.clone(), f.kernel.clone());
        let (ra, rb) = tokio::join!(
            tokio::spawn(async move { ka.load_plugin(&a, LoadOptions::default()).await }),
            tokio::spawn(async move { kb.load_plugin(&b, LoadOptions::default()).await }),
        );
        // Each swap, with the version it replaced.
        let mut swaps = Vec::new();
        for r in [ra.unwrap(), rb.unwrap()] {
            match r {
                Ok(o) => {
                    let replaced = o.replaced.expect("a reload");
                    swaps.push((replaced.previous.clone(), o.plugin_id.clone()));
                    drained(replaced.drained).await;
                }
                // 0.3.0 first: 0.2.0 is then a downgrade, refused before
                // its hook.
                Err(e) => assert!(matches!(e, RuntimeError::ReloadDowngrade { .. }), "{e}"),
            }
        }
        let loaded = f.kernel.list_plugins();
        assert_eq!(loaded.len(), 1, "{loaded:?}");
        let current = loaded[0].clone();

        // `Migrated` only for versions that swapped in.
        let mut migrated = Vec::new();
        while let Ok(Ok(env)) = tokio::time::timeout(Duration::from_millis(200), sub.recv()).await {
            if env.payload.phase == LifecyclePhase::Migrated {
                migrated.push(env.payload.plugin.clone());
            }
        }
        let swapped: Vec<PluginId> = swaps.iter().map(|(_, to)| to.clone()).collect();
        for m in &migrated {
            assert!(
                swapped.contains(m),
                "{m} migrated but never went live: {swaps:?}"
            );
        }
        // The data was last migrated by the version serving it, from the
        // version it replaced.
        let (from, _) = swaps.iter().find(|(_, to)| *to == current).unwrap();
        let data = f
            .root
            .join("data/plugins")
            .join(&v1.publisher)
            .join(&v1.name)
            .join("migrated");
        assert_eq!(
            std::fs::read_to_string(data).unwrap(),
            format!("{}->{}", from.version, current.version),
            "swaps {swaps:?}"
        );
    }
}

/// A ceiling lowered while a reload is under way never refuses the new
/// version after its migrate hook has run: either the reload is refused
/// before the hook (nothing migrated) or it completes and the lowering then
/// unloads it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ceiling_lowered_during_a_reload_never_strands_a_migration() {
    use entangle_types::tier::Tier;
    for _ in 0..4 {
        let f = Fixture::new();
        let caps = "\"storage.local\" = { mode = \"rw\" }";
        let (v1, v2) = (f.id("probe", "0.1.0"), f.id("probe", "0.2.0"));
        f.kernel
            .load_plugin_from_dir(&f.package("probe", "0.1.0", PROBE, 2, caps))
            .await
            .unwrap();
        let mut sub = f.kernel.bus().subscribe();
        let higher = f.package("probe", "0.2.0", PROBE, 3, caps);
        let k = f.kernel.clone();
        let reload = tokio::spawn(async move {
            k.load_plugin(
                &higher,
                LoadOptions {
                    accept_new_capabilities: true,
                    ..LoadOptions::default()
                },
            )
            .await
        });
        // Lower the ceiling below 0.2.0 as soon as it is registered.
        loop {
            let env = sub.recv().await.unwrap();
            if env.payload.plugin == v2 && env.payload.phase == LifecyclePhase::Registered {
                break;
            }
        }
        f.kernel
            .apply_max_tier(Tier::Sandboxed, true, None)
            .await
            .unwrap();
        let outcome = reload.await.unwrap();

        let mut phases = Vec::new();
        while let Ok(Ok(env)) = tokio::time::timeout(Duration::from_millis(200), sub.recv()).await {
            if env.payload.plugin == v2 {
                phases.push(env.payload.phase);
            }
        }
        let data = f
            .root
            .join("data/plugins")
            .join(&v1.publisher)
            .join(&v1.name)
            .join("migrated");
        match outcome {
            Ok(o) => {
                // It went live, then the lowering unloaded it.
                assert_eq!(o.plugin_id, v2);
                assert!(phases.contains(&LifecyclePhase::Loaded), "{phases:?}");
                assert_eq!(std::fs::read_to_string(&data).unwrap(), "0.1.0->0.2.0");
                assert!(f.kernel.list_plugins().is_empty());
            }
            Err(e) => {
                // Refused: nothing of 0.2.0 ran, 0.1.0 serves its data as is.
                assert!(e.to_string().contains("ENTANGLE-E0043"), "{e}");
                assert!(!phases.contains(&LifecyclePhase::Migrated), "{phases:?}");
                assert!(
                    !data.exists(),
                    "the refused version's hook migrated the data"
                );
                assert_eq!(f.kernel.list_plugins(), vec![v1.clone()]);
            }
        }
    }
}
