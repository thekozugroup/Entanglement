//! The OTLP/HTTP JSON exporter against an in-process collector.
//!
//! The collector is a real HTTP/1.1 server on a loopback port that records
//! every request and answers from a script of status codes, so the tests see
//! exactly what a production collector would.

use entangle_observability::catalog::names;
use entangle_observability::otel::{OtelConfig, OtelExporter};
use entangle_observability::Registry;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Response, StatusCode};
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use serde_json::Value;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::info_span;
use tracing_subscriber::prelude::*;

/// What the collector saw for one request.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl Seen {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("collector body is JSON")
    }
    fn spans(&self) -> Vec<Value> {
        self.json()["resourceSpans"][0]["scopeSpans"][0]["spans"]
            .as_array()
            .expect("spans array")
            .clone()
    }
}

/// How the collector answers: pop one `(status, retry_after)` per request;
/// when the script is empty answer 200.
#[derive(Default)]
struct Script {
    answers: VecDeque<(u16, Option<u64>)>,
    /// Accept requests but never answer (to stall the exporter).
    stall: bool,
}

struct Collector {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    script: Arc<Mutex<Script>>,
}

impl Collector {
    fn start(answers: &[(u16, Option<u64>)], stall: bool) -> Self {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let script = Arc::new(Mutex::new(Script {
            answers: answers.iter().copied().collect(),
            stall,
        }));
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let (s2, sc2) = (seen.clone(), script.clone());
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                addr_tx.send(listener.local_addr().unwrap()).unwrap();
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        continue;
                    };
                    let (seen, script) = (s2.clone(), sc2.clone());
                    tokio::spawn(async move {
                        let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                            let (seen, script) = (seen.clone(), script.clone());
                            async move {
                                let method = req.method().to_string();
                                let path = req.uri().path().to_owned();
                                let content_type = req
                                    .headers()
                                    .get("content-type")
                                    .and_then(|v| v.to_str().ok())
                                    .map(str::to_owned);
                                let body = req.into_body().collect().await.unwrap().to_bytes();
                                seen.lock().push(Seen {
                                    method,
                                    path,
                                    content_type,
                                    body: body.to_vec(),
                                });
                                let (stall, answer) = {
                                    let mut s = script.lock();
                                    (s.stall, s.answers.pop_front())
                                };
                                if stall {
                                    tokio::time::sleep(Duration::from_secs(30)).await;
                                }
                                let (status, retry_after) = answer.unwrap_or((200, None));
                                let mut resp = Response::builder()
                                    .status(StatusCode::from_u16(status).unwrap());
                                if let Some(secs) = retry_after {
                                    resp = resp.header("retry-after", secs.to_string());
                                }
                                Ok::<_, std::convert::Infallible>(
                                    resp.body(Full::new(Bytes::from_static(b"{}"))).unwrap(),
                                )
                            }
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), svc)
                            .await;
                    });
                }
            });
        });
        Self {
            addr: addr_rx.recv().unwrap(),
            seen,
            script,
        }
    }

    fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn requests(&self) -> Vec<Seen> {
        self.seen.lock().clone()
    }

    fn wait_for(&self, n: usize) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if self.seen.lock().len() >= n {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }
}

fn config(endpoint: String) -> OtelConfig {
    OtelConfig {
        endpoint,
        service_name: "entangle-test".into(),
        flush_interval: Duration::from_secs(3600),
        request_timeout: Duration::from_secs(2),
        backoff_base: Duration::from_millis(10),
        backoff_max: Duration::from_millis(80),
        ..OtelConfig::default()
    }
}

/// Run `f` with the exporter's layer installed as the thread's subscriber.
fn traced<R>(exporter: &OtelExporter, f: impl FnOnce() -> R) -> R {
    let sub = tracing_subscriber::registry().with(exporter.layer());
    tracing::subscriber::with_default(sub, f)
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[test]
fn posts_otlp_json_with_spec_shaped_ids_and_parent_linkage() {
    let collector = Collector::start(&[], false);
    let exporter = OtelExporter::start(&config(collector.endpoint())).unwrap();

    traced(&exporter, || {
        let outer = info_span!(
            "outer",
            job = "render",
            frames = 24u64,
            ratio = 0.5,
            ok = true
        );
        let _o = outer.enter();
        {
            let inner = info_span!("inner", otel.kind = "client");
            let _i = inner.enter();
            tracing::error!("inner failed");
        }
        let sibling = info_span!("sibling");
        drop(sibling);
    });
    assert!(exporter.flush());

    let reqs = collector.requests();
    assert_eq!(reqs.len(), 1, "one batch for three spans");
    let req = &reqs[0];
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/v1/traces");
    assert_eq!(req.content_type.as_deref(), Some("application/json"));

    let doc = req.json();
    let resource = &doc["resourceSpans"][0]["resource"]["attributes"];
    let service = resource
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["key"] == "service.name")
        .expect("service.name resource attribute");
    assert_eq!(service["value"]["stringValue"], "entangle-test");
    assert_eq!(
        doc["resourceSpans"][0]["scopeSpans"][0]["scope"]["name"],
        "entangle"
    );

    let spans = req.spans();
    assert_eq!(spans.len(), 3);
    let by_name = |n: &str| spans.iter().find(|s| s["name"] == n).unwrap().clone();
    let (outer, inner, sibling) = (by_name("outer"), by_name("inner"), by_name("sibling"));

    for s in &spans {
        let trace = s["traceId"].as_str().unwrap();
        let id = s["spanId"].as_str().unwrap();
        assert!(is_hex(trace, 32), "traceId is 32 lowercase hex: {trace}");
        assert!(is_hex(id, 16), "spanId is 16 lowercase hex: {id}");
        assert_ne!(trace, "0".repeat(32));
        // int64 fields are decimal strings in OTLP/JSON.
        let start = s["startTimeUnixNano"].as_str().unwrap();
        let end = s["endTimeUnixNano"].as_str().unwrap();
        assert!(start.bytes().all(|b| b.is_ascii_digit()) && !start.is_empty());
        assert!(end.parse::<u128>().unwrap() >= start.parse::<u128>().unwrap());
        assert!(s["kind"].is_u64());
    }

    // Parent linkage: inner and sibling are children of outer, in one trace.
    assert!(
        outer.get("parentSpanId").is_none(),
        "root span has no parent"
    );
    assert_eq!(inner["parentSpanId"], outer["spanId"]);
    assert_eq!(sibling["parentSpanId"], outer["spanId"]);
    assert_eq!(inner["traceId"], outer["traceId"]);
    assert_eq!(sibling["traceId"], outer["traceId"]);
    assert!(is_hex(inner["parentSpanId"].as_str().unwrap(), 16));

    // Kind, attributes, events, status.
    assert_eq!(inner["kind"], 3, "otel.kind = client");
    assert_eq!(outer["kind"], 1);
    let attr = |s: &Value, key: &str| {
        s["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["key"] == key)
            .map(|a| a["value"].clone())
    };
    assert_eq!(attr(&outer, "job").unwrap()["stringValue"], "render");
    assert_eq!(attr(&outer, "frames").unwrap()["intValue"], "24");
    assert_eq!(attr(&outer, "ratio").unwrap()["doubleValue"], 0.5);
    assert_eq!(attr(&outer, "ok").unwrap()["boolValue"], true);
    assert_eq!(
        inner["status"]["code"], 2,
        "an ERROR event marks the span failed"
    );
    assert_eq!(inner["status"]["message"], "inner failed");
    assert_eq!(inner["events"][0]["name"], "inner failed");
    assert!(outer.get("status").is_none());

    exporter.shutdown();
    assert_eq!(exporter.stats().exported(), 3);
}

#[test]
fn full_queue_drops_and_counts_without_blocking_the_caller() {
    // The collector never answers, so the worker is stuck on its first batch
    // and the 2-slot queue fills.
    let collector = Collector::start(&[], true);
    let cfg = OtelConfig {
        queue_capacity: 2,
        batch_size: 1,
        request_timeout: Duration::from_millis(300),
        max_retries: 0,
        ..config(collector.endpoint())
    };
    let exporter = OtelExporter::start(&cfg).unwrap();
    let registry = Registry::new();
    exporter.attach_metrics(&registry);

    let started = Instant::now();
    traced(&exporter, || {
        for i in 0..50u64 {
            let _s = info_span!("burst", i).entered();
        }
    });
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "recording spans must never wait for the collector (took {:?})",
        started.elapsed()
    );

    // At most the queue (2) plus the batch in flight (1) can be retained.
    let dropped = exporter.stats().dropped();
    assert!(
        (47..=49).contains(&dropped),
        "expected 47..=49 of 50 spans dropped, got {dropped}"
    );
    let text = registry.render();
    assert!(
        text.contains(&format!("{} {dropped}", names::OTLP_DROPPED)),
        "{text}"
    );
    assert!(text.contains(&format!("# TYPE {} counter", names::OTLP_DROPPED)));

    exporter.shutdown();
    // Spans after shutdown are dropped too, not queued forever.
    let before = exporter.stats().dropped();
    traced(&exporter, || drop(info_span!("late")));
    assert_eq!(exporter.stats().dropped(), before + 1);
}

#[test]
fn retries_503_with_backoff_then_succeeds() {
    let collector = Collector::start(&[(503, None), (503, None)], false);
    let exporter = OtelExporter::start(&config(collector.endpoint())).unwrap();
    traced(&exporter, || drop(info_span!("flaky")));
    assert!(exporter.flush());

    let reqs = collector.requests();
    assert_eq!(reqs.len(), 3, "two 503s then success");
    assert_eq!(reqs[0].body, reqs[2].body, "the same batch is resent");
    assert_eq!(exporter.stats().retries(), 2);
    assert_eq!(exporter.stats().exported(), 1);
    assert_eq!(exporter.stats().failed_batches(), 0);
    exporter.shutdown();
}

#[test]
fn gives_up_after_max_retries_on_persistent_5xx() {
    let collector = Collector::start(&[(500, None); 10], false);
    let cfg = OtelConfig {
        max_retries: 2,
        ..config(collector.endpoint())
    };
    let exporter = OtelExporter::start(&cfg).unwrap();
    traced(&exporter, || drop(info_span!("doomed")));
    assert!(exporter.flush());
    assert_eq!(collector.requests().len(), 3, "1 attempt + 2 retries");
    assert_eq!(exporter.stats().failed_batches(), 1);
    assert_eq!(exporter.stats().exported(), 0);
    exporter.shutdown();
}

#[test]
fn does_not_retry_a_400() {
    let collector = Collector::start(&[(400, None)], false);
    let exporter = OtelExporter::start(&config(collector.endpoint())).unwrap();
    traced(&exporter, || drop(info_span!("rejected")));
    assert!(exporter.flush());
    // Give a (wrongly) scheduled retry time to show up.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(collector.requests().len(), 1, "a 4xx is permanent");
    assert_eq!(exporter.stats().retries(), 0);
    assert_eq!(exporter.stats().failed_batches(), 1);
    exporter.shutdown();
}

#[test]
fn retries_429_honouring_a_capped_retry_after() {
    let collector = Collector::start(&[(429, Some(60))], false);
    let exporter = OtelExporter::start(&config(collector.endpoint())).unwrap();
    traced(&exporter, || drop(info_span!("throttled")));
    let started = Instant::now();
    assert!(exporter.flush());
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "Retry-After: 60 is capped at backoff_max"
    );
    assert_eq!(collector.requests().len(), 2);
    assert_eq!(exporter.stats().exported(), 1);
    exporter.shutdown();
}

#[test]
fn shutdown_flushes_queued_spans() {
    let collector = Collector::start(&[], false);
    // Huge batch and interval: nothing would be sent without the shutdown flush.
    let cfg = OtelConfig {
        batch_size: 1000,
        ..config(collector.endpoint())
    };
    let exporter = OtelExporter::start(&cfg).unwrap();
    traced(&exporter, || {
        for _ in 0..3 {
            drop(info_span!("pending"));
        }
    });
    assert!(collector.requests().is_empty(), "nothing flushed yet");
    exporter.shutdown();
    let reqs = collector.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].spans().len(), 3);
    assert_eq!(exporter.stats().exported(), 3);
    // Idempotent.
    exporter.shutdown();
}

#[test]
fn a_full_batch_is_sent_without_waiting_for_the_interval() {
    let collector = Collector::start(&[], false);
    let cfg = OtelConfig {
        batch_size: 2,
        ..config(collector.endpoint())
    };
    let exporter = OtelExporter::start(&cfg).unwrap();
    traced(&exporter, || {
        for _ in 0..4 {
            drop(info_span!("s"));
        }
    });
    assert!(collector.wait_for(2), "two size-triggered batches");
    assert!(collector.requests().iter().all(|r| r.spans().len() == 2));
    exporter.shutdown();
}

#[test]
fn the_flush_interval_sends_a_partial_batch() {
    let collector = Collector::start(&[], false);
    let cfg = OtelConfig {
        flush_interval: Duration::from_millis(100),
        ..config(collector.endpoint())
    };
    let exporter = OtelExporter::start(&cfg).unwrap();
    traced(&exporter, || drop(info_span!("lonely")));
    assert!(collector.wait_for(1), "interval flush");
    assert_eq!(collector.requests()[0].spans().len(), 1);
    exporter.shutdown();
}

#[test]
fn an_unreachable_collector_is_retried_then_abandoned() {
    // Bind and drop to get a port nothing listens on.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let cfg = OtelConfig {
        max_retries: 2,
        ..config(format!("http://127.0.0.1:{port}"))
    };
    let exporter = OtelExporter::start(&cfg).unwrap();
    traced(&exporter, || drop(info_span!("nowhere")));
    assert!(exporter.flush());
    assert_eq!(exporter.stats().retries(), 2);
    assert_eq!(exporter.stats().failed_batches(), 1);
    exporter.shutdown();
}

#[test]
fn a_base_path_in_the_endpoint_is_kept() {
    let collector = Collector::start(&[], false);
    let exporter = OtelExporter::start(&config(format!("{}/otlp/", collector.endpoint()))).unwrap();
    traced(&exporter, || drop(info_span!("pathy")));
    assert!(exporter.flush());
    assert_eq!(collector.requests()[0].path, "/otlp/v1/traces");
    exporter.shutdown();
    // Keep the script alive until here so the borrow checker sees it used.
    let _ = collector.script.lock().stall;
}
