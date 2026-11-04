//! Kernel-level capability resolution for wasm plugins (spec §4.5, §4.6).
//!
//! The kernel resolves a plugin's declared capabilities through the broker
//! once at load; what the plugin can then reach is derived from those grants
//! alone. A capability the operator's `deny_capabilities` policy refuses is
//! denied (audited) and the plugin loads without it; a grant that cannot be
//! realised fails the load with nothing left behind. Driven by the
//! `caps-probe` fixture from `entangle-host` (one result line per command),
//! and for streaming tasks by its `stream-plugin` twin `stream-caps-probe`
//! (one result chunk per command), which gets exactly the same grants.

use std::path::{Path, PathBuf};

use entangle_broker::{AuditEvent, GrantState};
use entangle_runtime::{Kernel, KernelConfig, NativeConfig, RuntimeError};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};

const PROBE: &[u8] = include_bytes!("../../entangle-host/tests/fixtures/caps-probe.wasm");
const STREAM_PROBE: &[u8] =
    include_bytes!("../../entangle-host/tests/fixtures/stream-caps-probe.wasm");

fn keyring_for(kp: &IdentityKeyPair) -> Keyring {
    let mut kr = Keyring::new();
    kr.add(TrustEntry {
        fingerprint: kp.fingerprint(),
        public_key: *kp.public().as_bytes(),
        publisher_name: "wasm-caps".into(),
        added_at: 0,
        note: String::new(),
    });
    kr
}

/// Write a signed wasm package declaring `caps`; returns the plugin id.
fn write_package(dir: &Path, kp: &IdentityKeyPair, caps: &str) -> String {
    write_component(dir, kp, "caps-probe", PROBE, caps)
}

/// Write a signed tier-3 package of `wasm` named `name` declaring `caps`;
/// returns the plugin id.
fn write_component(
    dir: &Path,
    kp: &IdentityKeyPair,
    name: &str,
    wasm: &[u8],
    caps: &str,
) -> String {
    let id = format!("{}/{name}@0.1.0", kp.fingerprint_hex());
    let manifest = format!(
        "[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = 3\nruntime = \"wasm\"\n\
         description = \"capability probe\"\n\n[capabilities]\n{caps}\n"
    );
    std::fs::write(dir.join("entangle.toml"), &manifest).unwrap();
    std::fs::write(dir.join("plugin.wasm"), wasm).unwrap();
    let bundle = sign_artifact(wasm, manifest.as_bytes(), kp);
    std::fs::write(
        dir.join("plugin.wasm.sig"),
        toml::to_string(&bundle).unwrap(),
    )
    .unwrap();
    id
}

fn kernel(kp: &IdentityKeyPair, data: Option<PathBuf>, deny: &[&str]) -> Kernel {
    Kernel::new(
        KernelConfig {
            denied_capabilities: deny.iter().map(|p| p.parse().unwrap()).collect(),
            native: NativeConfig {
                data_dir: data,
                ..NativeConfig::default()
            },
            ..KernelConfig::default()
        },
        keyring_for(kp),
    )
    .unwrap()
}

async fn run(k: &Kernel, id: &entangle_types::plugin_id::PluginId, script: &str) -> Vec<String> {
    let out = k
        .invoke(id, script.as_bytes(), 30_000)
        .await
        .expect("invoke");
    String::from_utf8(out)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

const CAPS: &str = r#""storage.local" = { mode = "rw" }
"net.wan" = { hosts = ["api.example.com:443"] }"#;

/// §4.5: a declared capability the operator denies does not stop the load;
/// it is denied (audited, visible in the report), never fetchable, and only
/// the granted capabilities are realised. Revocation then withdraws a
/// granted one for later invocations.
#[tokio::test(flavor = "multi_thread")]
async fn operator_denied_capability_loads_without_it_and_revocation_applies() {
    let kp = IdentityKeyPair::generate();
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("pkg");
    std::fs::create_dir_all(&pkg).unwrap();
    let data = tmp.path().join("data");
    write_package(&pkg, &kp, CAPS);
    let k = kernel(&kp, Some(data.clone()), &["net.wan"]);

    let id = k.load_plugin_from_dir(&pkg).await.expect("loads");

    let report = k.capability_report(&id).expect("loaded");
    let state = |key: &str| {
        report
            .iter()
            .find(|s| s.capability.key() == key)
            .unwrap_or_else(|| panic!("{key} in {report:?}"))
            .state
            .clone()
    };
    assert!(
        matches!(state("storage.local"), GrantState::Granted { ref grant_ids } if grant_ids.len() == 1),
        "{report:?}"
    );
    assert!(
        matches!(state("net.wan"), GrantState::Denied { ref reason } if reason.contains("net.wan")),
        "{report:?}"
    );
    let denied = k
        .broker()
        .audit_log()
        .snapshot()
        .into_iter()
        .any(|e| matches!(e, AuditEvent::CapabilityDenied { ref reason, .. } if reason.contains("operator policy")));
    assert!(denied, "the load-time denial is audited");

    let script = "write /data/a.txt from-kernel\n\
                  read /data/a.txt\n\
                  fetch net-wan\n\
                  fetch storage-local\n\
                  resolve localhost\n";
    let got = run(&k, &id, script).await;
    assert_eq!(got[0], "ok", "{got:?}");
    assert_eq!(got[1], "ok:from-kernel", "{got:?}");
    assert!(
        got[2].starts_with("err:not-granted:ENTANGLE-E0124"),
        "{got:?}"
    );
    assert!(got[3].starts_with("ok:"), "{got:?}");
    assert!(got[4].starts_with("err:"), "no net grant, no DNS: {got:?}");
    let on_disk = std::fs::canonicalize(&data)
        .unwrap()
        .join("plugins")
        .join(&id.publisher)
        .join(&id.name)
        .join("a.txt");
    assert_eq!(std::fs::read_to_string(on_disk).unwrap(), "from-kernel");

    let withdrawn = k.revoke_capability(&id, "storage.local").unwrap();
    assert_eq!(withdrawn.len(), 1, "the standing grant");
    let got = run(&k, &id, script).await;
    assert!(got[0].starts_with("err:"), "{got:?}");
    assert_eq!(got[3], "err:revoked:", "{got:?}");
    let report = k.capability_report(&id).unwrap();
    let local = report
        .iter()
        .find(|s| s.capability.key() == "storage.local")
        .unwrap();
    assert_eq!(local.state, GrantState::Revoked);

    k.unload(&id).await.unwrap();
    assert!(k.capability_report(&id).is_none());
}

/// A storage grant with nowhere to live (no data directory configured)
/// fails the load — `ENTANGLE-E0508` — and the broker registration is
/// rolled back, so the plugin can be loaded again once fixed.
#[tokio::test(flavor = "multi_thread")]
async fn unrealisable_grant_fails_the_load_and_rolls_back() {
    let kp = IdentityKeyPair::generate();
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("pkg");
    std::fs::create_dir_all(&pkg).unwrap();
    let id = write_package(&pkg, &kp, r#""storage.local" = {}"#);
    let k = kernel(&kp, None, &[]);
    let err = k.load_plugin_from_dir(&pkg).await.unwrap_err();
    assert!(matches!(err, RuntimeError::Host(_)), "{err}");
    assert!(err.to_string().contains("ENTANGLE-E0508"), "{err}");
    assert!(k.list_plugins().is_empty());
    assert!(k.capability_report(&id.parse().unwrap()).is_none());
}

/// Run `script` as one stream of a loaded `stream-caps-probe`: one result
/// chunk per command, then end the input.
async fn run_stream(
    k: &Kernel,
    id: &entangle_types::plugin_id::PluginId,
    script: &str,
) -> Result<Vec<String>, RuntimeError> {
    let steps = script.lines().filter(|l| !l.trim().is_empty()).count();
    let (port, mut driver) = entangle_host::stream_port(1);
    let run = k.invoke_stream(id, script.as_bytes(), port, 30_000);
    let collect = async {
        let mut out = Vec::new();
        for _ in 0..steps {
            let Some(chunk) = driver.chunks.recv().await else {
                break;
            };
            chunk.ack.sent();
            out.push(String::from_utf8(chunk.bytes).unwrap());
        }
        let _ = driver.input.send(entangle_host::StreamInput::End).await;
        out
    };
    let (ran, out) = tokio::join!(run, collect);
    ran.map(|_| out)
}

/// A stream plugin's declared capabilities are resolved at load exactly as
/// a one-shot plugin's: granted ones are realised (its `/data` is the same
/// on-disk directory, created at load), operator-denied ones are absent and
/// unfetchable, and a revocation applies to the next stream.
#[tokio::test(flavor = "multi_thread")]
async fn a_stream_plugin_gets_the_grants_of_a_one_shot_plugin() {
    let kp = IdentityKeyPair::generate();
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("pkg");
    std::fs::create_dir_all(&pkg).unwrap();
    let data = tmp.path().join("data");
    write_component(&pkg, &kp, "stream-caps-probe", STREAM_PROBE, CAPS);
    let k = kernel(&kp, Some(data.clone()), &["net.wan"]);
    let id = k.load_plugin_from_dir(&pkg).await.expect("loads");
    assert_eq!(k.plugin_world(&id), Some("stream-plugin"));
    let dir = data.join("plugins").join(&id.publisher).join(&id.name);
    assert!(dir.is_dir(), "the storage grant is realised at load");

    let script = "write /data/s.txt via-stream\n\
                  read /data/s.txt\n\
                  fetch net-wan\n\
                  fetch storage-local\n\
                  resolve api.example.com\n";
    let got = run_stream(&k, &id, script).await.expect("stream runs");
    assert_eq!(got[0], "ok", "{got:?}");
    assert_eq!(got[1], "ok:via-stream", "{got:?}");
    assert!(
        got[2].starts_with("err:not-granted:ENTANGLE-E0124"),
        "{got:?}"
    );
    assert!(got[3].starts_with("ok:"), "{got:?}");
    assert!(got[4].starts_with("err:"), "net.wan was denied: {got:?}");
    assert_eq!(
        std::fs::read_to_string(dir.join("s.txt")).unwrap(),
        "via-stream"
    );

    k.revoke_capability(&id, "storage.local").unwrap();
    let got = run_stream(&k, &id, "read /data/s.txt\nfetch storage-local\n")
        .await
        .expect("stream runs");
    assert!(got[0].starts_with("err:"), "{got:?}");
    assert_eq!(got[1], "err:revoked:", "{got:?}");
    k.unload(&id).await.unwrap();
}

/// A stream plugin's storage grant with nowhere to live fails its load
/// (`ENTANGLE-E0508`) and rolls the registration back, as for a one-shot
/// plugin.
#[tokio::test(flavor = "multi_thread")]
async fn a_stream_plugins_unrealisable_grant_fails_the_load() {
    let kp = IdentityKeyPair::generate();
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("pkg");
    std::fs::create_dir_all(&pkg).unwrap();
    let id = write_component(
        &pkg,
        &kp,
        "stream-caps-probe",
        STREAM_PROBE,
        r#""storage.local" = {}"#,
    );
    let k = kernel(&kp, None, &[]);
    let err = k.load_plugin_from_dir(&pkg).await.unwrap_err();
    assert!(err.to_string().contains("ENTANGLE-E0508"), "{err}");
    assert!(k.list_plugins().is_empty());
    assert!(k.capability_report(&id.parse().unwrap()).is_none());
}

/// Poll `cond` every 10 ms for up to 10 s.
async fn eventually(mut cond: impl FnMut() -> bool) -> bool {
    for _ in 0..1_000 {
        if cond() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    cond()
}

/// The next chunk of a stream, acknowledged, as text.
async fn next_chunk(driver: &mut entangle_host::StreamPortDriver) -> Option<String> {
    let chunk = tokio::time::timeout(std::time::Duration::from_secs(30), driver.chunks.recv())
        .await
        .expect("a chunk within 30 s")?;
    chunk.ack.sent();
    Some(String::from_utf8(chunk.bytes).unwrap())
}

fn audited(k: &Kernel, pred: impl Fn(&AuditEvent) -> bool) -> usize {
    k.broker()
        .audit_log()
        .snapshot()
        .iter()
        .filter(|e| pred(e))
        .count()
}

/// §9.4.1 with §4.5: once the ceiling is lowered below a plugin, the
/// broker's per-grant check uses the new ceiling — the plugin's fetches are
/// refused (`ENTANGLE-E0127`) while it drains — but a stream it is running
/// without network still completes (the lowering waits for it), keeping
/// the directory it had open, as after a revocation. Its grants are released
/// (audited) by the unload that follows the drain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lowered_ceiling_refuses_new_fetches_while_the_plugin_drains() {
    use entangle_types::tier::Tier;
    let kp = IdentityKeyPair::generate();
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("pkg");
    std::fs::create_dir_all(&pkg).unwrap();
    let data = tmp.path().join("data");
    write_component(
        &pkg,
        &kp,
        "stream-caps-probe",
        STREAM_PROBE,
        r#""storage.local" = { mode = "rw" }"#,
    );
    let k = std::sync::Arc::new(kernel(&kp, Some(data.clone()), &[]));
    let id = k.load_plugin_from_dir(&pkg).await.expect("loads");

    let (port, mut driver) = entangle_host::stream_port(1);
    let (kk, pid) = (k.clone(), id.clone());
    let stream = tokio::spawn(async move {
        kk.invoke_stream(
            &pid,
            b"fetch storage-local\nwrite /data/a.txt before\n",
            port,
            30_000,
        )
        .await
    });
    assert!(next_chunk(&mut driver).await.unwrap().starts_with("ok:"));
    assert_eq!(next_chunk(&mut driver).await.unwrap(), "ok");

    let kk = k.clone();
    let lowering =
        tokio::spawn(async move { kk.apply_max_tier(Tier::Sandboxed, true, None).await });
    assert!(eventually(|| k.max_tier_allowed() == Tier::Sandboxed).await);

    driver
        .input
        .send(entangle_host::StreamInput::Chunk(
            b"fetch storage-local\nwrite /data/a.txt during\nread /data/a.txt\n".to_vec(),
        ))
        .await
        .expect("the plugin reads its input");
    let refused = next_chunk(&mut driver).await.unwrap();
    assert!(
        refused.starts_with("err:not-granted:ENTANGLE-E0127"),
        "a fetch above the lowered ceiling: {refused}"
    );
    assert_eq!(next_chunk(&mut driver).await.unwrap(), "ok");
    assert_eq!(next_chunk(&mut driver).await.unwrap(), "ok:during");
    assert!(!lowering.is_finished(), "the lowering waits for the stream");
    assert_eq!(
        k.broker().registered_tiers().len(),
        1,
        "the registration (and grants) outlive the running stream"
    );

    driver
        .input
        .send(entangle_host::StreamInput::End)
        .await
        .expect("the plugin reads its input");
    let ran = stream.await.unwrap();
    assert!(ran.is_ok(), "the drained stream completes: {ran:?}");
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(30), lowering)
        .await
        .expect("the lowering completes once the stream ended")
        .unwrap()
        .expect("unload authorised");
    assert_eq!(outcome.unloaded, vec![id.clone()]);
    assert!(k.broker().registered_tiers().is_empty());
    assert!(audited(&k, |e| e.code() == Some("ENTANGLE-W0214")) == 1);
    // The handle the stream fetched (released when its instance ended) and
    // the standing grant (released by the unload).
    assert_eq!(
        audited(
            &k,
            |e| matches!(e, AuditEvent::CapabilityReleased { plugin, .. } if *plugin == id)
        ),
        2
    );
}

/// §9.4.1 with §4.6: a ceiling lowered below a plugin stops its in-flight
/// network use exactly as a revocation does: a stream running on a
/// `net.lan` grant is stopped at once (`ENTANGLE-E0511`) instead of being
/// drained until it ends, so the lowering completes promptly, and only then
/// does the unload release its grants and audit it (`ENTANGLE-W0214`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lowered_ceiling_stops_a_networked_stream_like_a_revocation() {
    use entangle_types::tier::Tier;
    let kp = IdentityKeyPair::generate();
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("pkg");
    std::fs::create_dir_all(&pkg).unwrap();
    write_component(
        &pkg,
        &kp,
        "stream-caps-probe",
        STREAM_PROBE,
        r#""net.lan" = {}"#,
    );
    let k = std::sync::Arc::new(kernel(&kp, None, &[]));
    let id = k.load_plugin_from_dir(&pkg).await.expect("loads");

    let (port, mut driver) = entangle_host::stream_port(1);
    let (kk, pid) = (k.clone(), id.clone());
    let stream = tokio::spawn(async move {
        kk.invoke_stream(&pid, b"fetch net-lan\n", port, 30_000)
            .await
    });
    assert!(next_chunk(&mut driver).await.unwrap().starts_with("ok:"));
    // The plugin is now parked in `next-chunk`, holding its network grant.

    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        k.apply_max_tier(Tier::Sandboxed, true, None),
    )
    .await
    .expect("the lowering does not wait out the 30 s stream")
    .expect("unload authorised");
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    assert_eq!(outcome.unloaded, vec![id.clone()]);
    let err = stream
        .await
        .unwrap()
        .expect_err("the networked stream is stopped by the lowering");
    assert!(
        matches!(
            err,
            RuntimeError::Host(entangle_host::HostError::CapabilityRevoked { ref capability })
                if capability == "net.lan"
        ),
        "{err}"
    );
    assert!(err.to_string().contains("ENTANGLE-E0511"), "{err}");
    assert!(
        next_chunk(&mut driver).await.is_none(),
        "the stream's port is closed"
    );

    // Released by the unload, after the stream stopped: the standing grant
    // and the fetched handle; then the plugin is reported unloaded.
    let events = k.broker().audit_log().snapshot();
    let pos = |pred: &dyn Fn(&AuditEvent) -> bool| events.iter().rposition(pred);
    let released =
        pos(&|e| matches!(e, AuditEvent::CapabilityReleased { plugin, .. } if *plugin == id));
    let w0214 = pos(&|e| e.code() == Some("ENTANGLE-W0214"));
    assert!(
        matches!((released, w0214), (Some(r), Some(w)) if r < w),
        "{events:?}"
    );
    assert_eq!(
        audited(
            &k,
            |e| matches!(e, AuditEvent::CapabilityReleased { plugin, .. } if *plugin == id)
        ),
        2
    );
    assert!(k.broker().registered_tiers().is_empty());
    assert!(k.list_plugins().is_empty());
}

/// A plugin left above a ceiling lowered without unloading it (the broker's
/// ceiling changed directly) is suspended, not run: invocations are refused
/// with `ENTANGLE-E0043` until the ceiling is raised again.
#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_above_the_ceiling_in_force_is_suspended() {
    use entangle_types::tier::Tier;
    let kp = IdentityKeyPair::generate();
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("pkg");
    std::fs::create_dir_all(&pkg).unwrap();
    write_package(&pkg, &kp, "");
    let k = kernel(&kp, None, &[]);
    let id = k.load_plugin_from_dir(&pkg).await.expect("loads");
    assert_eq!(run(&k, &id, "fetch net-lan\n").await.len(), 1);

    k.broker().set_max_tier_allowed(Tier::Sandboxed);
    let err = k.invoke(&id, b"fetch net-lan\n", 30_000).await.unwrap_err();
    assert!(err.to_string().contains("ENTANGLE-E0043"), "{err}");
    let (port, _driver) = entangle_host::stream_port(1);
    let err = k.invoke_stream(&id, b"", port, 30_000).await.unwrap_err();
    assert!(err.to_string().contains("ENTANGLE-E0043"), "{err}");

    k.broker().set_max_tier_allowed(Tier::Native);
    assert_eq!(run(&k, &id, "fetch net-lan\n").await.len(), 1);
}
