//! Streaming invocations are observable like one-shot ones: a
//! `plugin.invoke` span (with `world = "stream-plugin"`) and the
//! stream-invocation metrics, scraped from the registry's Prometheus text.
//!
//! Driven by the `stream-caps-probe` fixture from `entangle-host`: its input
//! is a script, it yields one chunk per command and returns when its input
//! ends.

use std::path::Path;
use std::sync::{Arc, Once, OnceLock};
use std::time::Duration;

use entangle_observability::catalog::names;
use entangle_observability::context::{AttrValue, SpanLayer, SpanRecord, SpanSink};
use entangle_observability::Registry;
use entangle_runtime::{Kernel, KernelConfig, RuntimeError};
use entangle_signing::{sign_artifact, IdentityKeyPair, Keyring, TrustEntry};
use entangle_types::plugin_id::PluginId;
use parking_lot::Mutex;

const STREAM_PROBE: &[u8] =
    include_bytes!("../../entangle-host/tests/fixtures/stream-caps-probe.wasm");
const ONE_SHOT_PROBE: &[u8] = include_bytes!("../../entangle-host/tests/fixtures/caps-probe.wasm");

// ── span capture ────────────────────────────────────────────────────────────

#[derive(Default)]
struct Spans(Mutex<Vec<SpanRecord>>);

impl SpanSink for Spans {
    fn emit(&self, span: SpanRecord) {
        self.0.lock().push(span);
    }
}

/// The process-wide span sink (this test binary owns the subscriber).
fn spans() -> &'static Arc<Spans> {
    use tracing_subscriber::prelude::*;
    static SINK: OnceLock<Arc<Spans>> = OnceLock::new();
    static INIT: Once = Once::new();
    let sink = SINK.get_or_init(|| Arc::new(Spans::default()));
    INIT.call_once(|| {
        let sub = tracing_subscriber::registry().with(SpanLayer::new(sink.clone()));
        tracing::subscriber::set_global_default(sub).expect("this test binary owns the subscriber");
    });
    sink
}

fn attr(span: &SpanRecord, key: &str) -> Option<String> {
    span.attributes
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| match v {
            AttrValue::Str(s) => s.clone(),
            other => format!("{other:?}"),
        })
}

/// Finished `plugin.invoke` spans for `plugin`.
fn invoke_spans(plugin: &PluginId) -> Vec<SpanRecord> {
    let plugin = plugin.to_string();
    spans()
        .0
        .lock()
        .iter()
        .filter(|s| s.name == "plugin.invoke" && attr(s, "plugin").as_deref() == Some(&plugin))
        .cloned()
        .collect()
}

// ── kernel and packages ─────────────────────────────────────────────────────

fn keyring_for(kp: &IdentityKeyPair) -> Keyring {
    let mut kr = Keyring::new();
    kr.add(TrustEntry {
        fingerprint: kp.fingerprint(),
        public_key: *kp.public().as_bytes(),
        publisher_name: "stream-observability".into(),
        added_at: 0,
        note: String::new(),
    });
    kr
}

fn write_component(dir: &Path, kp: &IdentityKeyPair, name: &str, wasm: &[u8]) -> PluginId {
    let id = format!("{}/{name}@0.1.0", kp.fingerprint_hex());
    let manifest = format!(
        "[plugin]\nid = \"{id}\"\nversion = \"0.1.0\"\ntier = 1\nruntime = \"wasm\"\n\
         description = \"stream observability probe\"\n"
    );
    std::fs::write(dir.join("entangle.toml"), &manifest).unwrap();
    std::fs::write(dir.join("plugin.wasm"), wasm).unwrap();
    let bundle = sign_artifact(wasm, manifest.as_bytes(), kp);
    std::fs::write(
        dir.join("plugin.wasm.sig"),
        toml::to_string(&bundle).unwrap(),
    )
    .unwrap();
    id.parse().unwrap()
}

async fn load(kernel: &Kernel, kp: &IdentityKeyPair, name: &str, wasm: &[u8]) -> PluginId {
    let dir = tempfile::tempdir().unwrap();
    let id = write_component(dir.path(), kp, name, wasm);
    let loaded = kernel.load_plugin_from_dir(dir.path()).await.unwrap();
    assert_eq!(loaded, id);
    id
}

/// The value of one sample line in the Prometheus text `scrape`.
fn sample(scrape: &str, family: &str, labels: &[(&str, &str)]) -> Option<f64> {
    scrape.lines().find_map(|line| {
        let rest = line.strip_prefix(family)?.strip_prefix('{')?;
        let (set, value) = rest.split_once("} ")?;
        let all = labels
            .iter()
            .all(|(k, v)| set.split(',').any(|kv| kv == format!("{k}=\"{v}\"")));
        let count = set.split(',').count();
        (all && count == labels.len()).then(|| value.trim().parse().ok())?
    })
}

/// A streaming invocation is wrapped in a `plugin.invoke` span carrying
/// `world = "stream-plugin"`, and is counted — by bounded `plugin` label and
/// outcome, with its duration — in the stream-invocation families of the
/// registry the daemon scrapes: `ok` when the plugin returns, `cancelled`
/// when the stream is torn down first, `error` (plus the error-class
/// counter) when it fails. One-shot invocations keep their own families.
#[tokio::test(flavor = "multi_thread")]
async fn stream_invocations_get_a_span_and_scrapeable_metrics() {
    spans();
    let kp = IdentityKeyPair::generate();
    let registry = Registry::new();
    let kernel = Kernel::new(KernelConfig::default(), keyring_for(&kp))
        .unwrap()
        .with_metrics(registry.clone());
    let stream = load(&kernel, &kp, "stream-caps-probe", STREAM_PROBE).await;
    let one_shot = load(&kernel, &kp, "caps-probe", ONE_SHOT_PROBE).await;

    // ── a stream that runs to completion: one chunk, then the input ends.
    let (port, mut driver) = entangle_host::stream_port(1);
    let run = kernel.invoke_stream(&stream, b"fetch storage-local\n", port, 30_000);
    let drive = async {
        let chunk = tokio::time::timeout(Duration::from_secs(30), driver.chunks.recv())
            .await
            .expect("a chunk within 30 s")
            .expect("one chunk per command");
        chunk.ack.sent();
        driver
            .input
            .send(entangle_host::StreamInput::End)
            .await
            .unwrap();
    };
    let (ran, ()) = tokio::join!(run, drive);
    ran.expect("the stream completes");

    // ── a stream torn down before the plugin returns.
    let (port, mut driver) = entangle_host::stream_port(1);
    let mut running =
        Box::pin(kernel.invoke_stream(&stream, b"fetch storage-local\n", port, 30_000));
    tokio::select! {
        r = &mut running => panic!("the plugin waits for its input to end, got {r:?}"),
        chunk = driver.chunks.recv() => chunk.expect("first chunk").ack.sent(),
    }
    drop(running); // the stream is torn down mid-flight

    // ── a stream call that fails: a one-shot plugin cannot stream.
    let (port, _driver) = entangle_host::stream_port(1);
    let err = kernel
        .invoke_stream(&one_shot, b"", port, 30_000)
        .await
        .unwrap_err();
    assert!(matches!(err, RuntimeError::WrongWorld { .. }), "{err}");

    // ── a one-shot call still lands in the one-shot families only.
    kernel
        .invoke(&one_shot, b"fetch storage-local\n", 30_000)
        .await
        .expect("one-shot invoke");

    let scrape = registry.render();
    let s = stream.to_string();
    let o = one_shot.to_string();
    let streams = |plugin: &str, outcome: &str| {
        sample(
            &scrape,
            names::PLUGIN_STREAMS,
            &[("plugin", plugin), ("outcome", outcome)],
        )
    };
    assert_eq!(streams(&s, "ok"), Some(1.0), "{scrape}");
    assert_eq!(streams(&s, "cancelled"), Some(1.0), "{scrape}");
    assert_eq!(streams(&s, "error"), None, "{scrape}");
    assert_eq!(streams(&o, "error"), Some(1.0), "{scrape}");
    assert_eq!(
        sample(
            &scrape,
            &format!("{}_count", names::PLUGIN_STREAM_DURATION),
            &[("plugin", &s)],
        ),
        Some(2.0),
        "both streams of the stream plugin are timed: {scrape}"
    );
    let class = entangle_observability::catalog::code_class(&err.to_string());
    assert_eq!(
        sample(
            &scrape,
            names::PLUGIN_ERRORS,
            &[("plugin", &o), ("class", &class)]
        ),
        Some(1.0),
        "{scrape}"
    );
    assert_eq!(
        sample(
            &scrape,
            names::PLUGIN_INVOCATIONS,
            &[("plugin", &s), ("outcome", "ok")]
        ),
        None,
        "streams are not one-shot invocations: {scrape}"
    );
    assert_eq!(
        sample(
            &scrape,
            names::PLUGIN_INVOCATIONS,
            &[("plugin", &o), ("outcome", "ok")]
        ),
        Some(1.0),
        "{scrape}"
    );

    // ── spans: one per invocation, labelled with the world.
    let stream_spans = invoke_spans(&stream);
    assert_eq!(stream_spans.len(), 2, "{stream_spans:?}");
    for span in &stream_spans {
        assert_eq!(attr(span, "world").as_deref(), Some("stream-plugin"));
        assert!(
            span.attributes
                .iter()
                .any(|(k, v)| k == "input_bytes" && *v == AttrValue::Int(20)),
            "{span:?}"
        );
    }
    let one_shot_spans = invoke_spans(&one_shot);
    assert_eq!(one_shot_spans.len(), 2, "{one_shot_spans:?}");
    let worlds: Vec<_> = one_shot_spans
        .iter()
        .filter_map(|s| attr(s, "world"))
        .collect();
    assert!(
        worlds.contains(&"stream-plugin".to_owned()) && worlds.contains(&"plugin".to_owned()),
        "the failed stream call and the one-shot call are both spanned, each with its world: \
         {worlds:?}"
    );
}
