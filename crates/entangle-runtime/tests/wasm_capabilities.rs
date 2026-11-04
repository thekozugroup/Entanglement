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
