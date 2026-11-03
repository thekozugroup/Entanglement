//! OpenTelemetry trace export over OTLP/HTTP with JSON encoding (spec §9.6).
//!
//! This module exports `tracing` spans to an OpenTelemetry collector without
//! the `opentelemetry` crates: finished spans from [`crate::context::SpanLayer`]
//! are queued, batched, encoded as the OTLP/HTTP JSON `ExportTraceServiceRequest`
//! (`resourceSpans` / `scopeSpans` / `spans`) and `POST`ed to
//! `<endpoint>/v1/traces` with `Content-Type: application/json`.
//!
//! # Delivery behaviour
//!
//! * **Bounded queue.** Spans wait in a queue of
//!   [`OtelConfig::queue_capacity`]. A full queue drops the new span and
//!   counts it ([`ExporterStats::dropped`]); recording a span never blocks
//!   the instrumented code.
//! * **Batching.** A batch is sent when it reaches
//!   [`OtelConfig::batch_size`] spans or every
//!   [`OtelConfig::flush_interval`], whichever is first.
//! * **Timeout.** Each attempt (connect, request, response) is bounded by
//!   [`OtelConfig::request_timeout`].
//! * **Retry.** `429` and `5xx` responses, and transport failures (a refused
//!   connection or a timeout while the collector restarts), are retried with
//!   exponential backoff (`backoff_base`, doubling, capped at `backoff_max`;
//!   a `Retry-After` header of whole seconds is honoured up to that cap) up to
//!   [`OtelConfig::max_retries`] times. Every other `4xx` is permanent: the
//!   batch is dropped and counted, never retried.
//! * **Shutdown.** [`OtelExporter::shutdown`] drains the queue and sends the
//!   remaining spans before returning (bounded by the same timeouts).
//!
//! Export runs on its own thread with a private current-thread runtime, so
//! it works whether or not the caller is inside a Tokio runtime.
//!
//! # Limits
//!
//! Only `http://` endpoints are supported: there is no TLS client in the
//! exporter. Point it at a local collector or agent (the usual deployment)
//! and let that forward over TLS.

use crate::context::{AttrValue, SpanLayer, SpanRecord, SpanSink, SpanStatus};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, RETRY_AFTER, USER_AGENT};
use hyper::{Request, Uri};
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Default OTLP/HTTP endpoint. (`4317` is OTLP/gRPC and is not spoken here.)
pub const DEFAULT_ENDPOINT: &str = "http://localhost:4318";

/// Configuration for the OTLP exporter.
#[derive(Clone, Debug)]
pub struct OtelConfig {
    /// OTLP/HTTP base endpoint, e.g. `http://localhost:4318`. Spans are
    /// posted to `<endpoint>/v1/traces`.
    pub endpoint: String,
    /// Logical service name (`service.name` resource attribute).
    pub service_name: String,
    /// Spans the queue holds before new ones are dropped.
    pub queue_capacity: usize,
    /// Spans per request.
    pub batch_size: usize,
    /// Longest a span waits for a batch to fill.
    pub flush_interval: Duration,
    /// Bound on one export attempt.
    pub request_timeout: Duration,
    /// Retries after the first attempt (so up to `1 + max_retries` attempts).
    pub max_retries: u32,
    /// First backoff; doubles per retry.
    pub backoff_base: Duration,
    /// Backoff ceiling (also caps `Retry-After`).
    pub backoff_max: Duration,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            endpoint: DEFAULT_ENDPOINT.to_string(),
            service_name: "entangled".to_string(),
            queue_capacity: 2048,
            batch_size: 256,
            flush_interval: Duration::from_secs(5),
            request_timeout: Duration::from_secs(10),
            max_retries: 3,
            backoff_base: Duration::from_millis(250),
            backoff_max: Duration::from_secs(10),
        }
    }
}

/// Errors surfaced by the OTEL exporter.
///
/// `ENTANGLE-E0650` (the "not implemented" scaffold error) is retired and
/// will not be reused.
#[derive(Debug, thiserror::Error)]
pub enum OtelError {
    /// The `endpoint` field could not be parsed as a URL or has the wrong scheme.
    #[error("ENTANGLE-E0651: invalid endpoint {endpoint:?}: {reason}")]
    InvalidEndpoint {
        /// The offending endpoint string.
        endpoint: String,
        /// Operator-facing reason.
        reason: &'static str,
    },
    /// The `service_name` field is empty.
    #[error("ENTANGLE-E0652: service_name must be non-empty")]
    EmptyServiceName,
    /// A tuning field is out of range (zero queue, zero batch, ...).
    #[error("ENTANGLE-E0653: invalid exporter setting {field}: {reason}")]
    InvalidSetting {
        /// The offending field.
        field: &'static str,
        /// Operator-facing reason.
        reason: &'static str,
    },
    /// The export thread could not be started.
    #[error("ENTANGLE-E0654: could not start the OTLP exporter: {0}")]
    StartFailed(String),
}

/// The parsed pieces of a validated endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Target {
    host: String,
    port: u16,
    authority: String,
    path: String,
}

fn parse_endpoint(endpoint: &str) -> Result<Target, OtelError> {
    let bad = |reason: &'static str| OtelError::InvalidEndpoint {
        endpoint: endpoint.to_owned(),
        reason,
    };
    let lower = endpoint.to_ascii_lowercase();
    if lower.starts_with("https://") {
        return Err(bad(
            "endpoint must start with http:// — https:// is not supported by the built-in \
             exporter (no TLS client); send to a local collector over http://",
        ));
    }
    if !lower.starts_with("http://") {
        return Err(bad("endpoint must start with http://"));
    }
    let uri: Uri = endpoint
        .parse()
        .map_err(|_| bad("endpoint is not a valid URL"))?;
    let authority = uri
        .authority()
        .ok_or_else(|| bad("endpoint host is empty"))?;
    // `Uri::host` keeps the brackets of an IPv6 literal.
    let host = authority.host();
    if host.is_empty() {
        return Err(bad("endpoint host is empty"));
    }
    // `http` reads an out-of-range port as "no port"; catch that here rather
    // than silently dialling port 80.
    if let Some((_, tail)) = authority.as_str().rsplit_once(':') {
        let looks_like_port = !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit());
        if looks_like_port && authority.port_u16().is_none() {
            return Err(bad("endpoint port is out of range"));
        }
    }
    if authority.as_str().contains('@') {
        return Err(bad("endpoint must not contain credentials"));
    }
    if uri.query().is_some() || endpoint.contains('#') {
        return Err(bad("endpoint must not contain a query or fragment"));
    }
    let base = uri.path().trim_end_matches('/');
    Ok(Target {
        host: host.trim_matches(|c| c == '[' || c == ']').to_owned(),
        port: authority.port_u16().unwrap_or(80),
        authority: authority.as_str().to_owned(),
        path: format!("{base}/v1/traces"),
    })
}

/// Validate an [`OtelConfig`] without starting the exporter.
///
/// Misconfiguration is reported at startup, not at the first exported span.
pub fn validate(cfg: &OtelConfig) -> Result<(), OtelError> {
    if cfg.service_name.trim().is_empty() {
        return Err(OtelError::EmptyServiceName);
    }
    parse_endpoint(&cfg.endpoint)?;
    let setting = |field, reason| Err(OtelError::InvalidSetting { field, reason });
    if cfg.queue_capacity == 0 {
        return setting("queue_capacity", "must be at least 1");
    }
    if cfg.batch_size == 0 {
        return setting("batch_size", "must be at least 1");
    }
    if cfg.flush_interval.is_zero() {
        return setting("flush_interval", "must be non-zero");
    }
    if cfg.request_timeout.is_zero() {
        return setting("request_timeout", "must be non-zero");
    }
    Ok(())
}

// ── statistics ───────────────────────────────────────────────────────────────

/// Counters describing the exporter's health.
#[derive(Debug, Default)]
pub struct ExporterStats {
    dropped: AtomicU64,
    exported: AtomicU64,
    failed_batches: AtomicU64,
    retries: AtomicU64,
}

impl ExporterStats {
    /// Spans dropped because the queue was full (or the exporter was shut down).
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
    /// Spans delivered to the collector.
    pub fn exported(&self) -> u64 {
        self.exported.load(Ordering::Relaxed)
    }
    /// Batches abandoned after a permanent error or exhausted retries.
    pub fn failed_batches(&self) -> u64 {
        self.failed_batches.load(Ordering::Relaxed)
    }
    /// Retry attempts made so far.
    pub fn retries(&self) -> u64 {
        self.retries.load(Ordering::Relaxed)
    }
}

// ── OTLP JSON encoding ───────────────────────────────────────────────────────

fn any_value(v: &AttrValue) -> Value {
    match v {
        AttrValue::Str(s) => json!({ "stringValue": s }),
        // OTLP/JSON encodes int64 as a decimal string.
        AttrValue::Int(i) => json!({ "intValue": i.to_string() }),
        AttrValue::Double(d) if d.is_finite() => json!({ "doubleValue": d }),
        AttrValue::Double(d) => json!({ "stringValue": d.to_string() }),
        AttrValue::Bool(b) => json!({ "boolValue": b }),
    }
}

fn key_values(attrs: &[(String, AttrValue)]) -> Value {
    Value::Array(
        attrs
            .iter()
            .map(|(k, v)| json!({ "key": k, "value": any_value(v) }))
            .collect(),
    )
}

fn encode_span(s: &SpanRecord) -> Value {
    let mut span = json!({
        "traceId": crate::context::hex_string(&s.trace_id),
        "spanId": crate::context::hex_string(&s.span_id),
        "name": s.name,
        "kind": s.kind.otlp(),
        "startTimeUnixNano": SpanRecord::unix_nanos(s.start).to_string(),
        "endTimeUnixNano": SpanRecord::unix_nanos(s.end).to_string(),
        "attributes": key_values(&s.attributes),
        "events": s.events.iter().map(|e| json!({
            "timeUnixNano": SpanRecord::unix_nanos(e.time).to_string(),
            "name": e.name,
            "attributes": key_values(&e.attributes),
        })).collect::<Vec<_>>(),
    });
    // The wire format omits the parent for a root span (an empty string is
    // also legal, but absent is what every SDK sends).
    if let (Some(parent), Some(obj)) = (s.parent_span_id, span.as_object_mut()) {
        obj.insert(
            "parentSpanId".to_owned(),
            Value::String(crate::context::hex_string(&parent)),
        );
    }
    match &s.status {
        SpanStatus::Unset => {}
        SpanStatus::Ok => {
            span["status"] = json!({ "code": 1 });
        }
        SpanStatus::Error(message) => {
            span["status"] = json!({ "code": 2, "message": message });
        }
    }
    span
}

/// Encode `spans` as an OTLP/HTTP JSON `ExportTraceServiceRequest`.
pub fn encode_batch(service_name: &str, instance_id: &str, spans: &[SpanRecord]) -> Vec<u8> {
    let body = json!({
        "resourceSpans": [{
            "resource": { "attributes": [
                { "key": "service.name", "value": { "stringValue": service_name } },
                { "key": "service.version", "value": { "stringValue": env!("CARGO_PKG_VERSION") } },
                { "key": "service.instance.id", "value": { "stringValue": instance_id } },
                { "key": "telemetry.sdk.name", "value": { "stringValue": "entangle-observability" } },
                { "key": "telemetry.sdk.language", "value": { "stringValue": "rust" } },
            ] },
            "scopeSpans": [{
                "scope": { "name": "entangle", "version": env!("CARGO_PKG_VERSION") },
                "spans": spans.iter().map(encode_span).collect::<Vec<_>>(),
            }],
        }],
    });
    // Serialising a `Value` cannot fail.
    serde_json::to_vec(&body).unwrap_or_default()
}

// ── the exporter ─────────────────────────────────────────────────────────────

enum Msg {
    Span(Box<SpanRecord>),
    Flush(mpsc::Sender<()>),
    Shutdown(mpsc::Sender<()>),
}

struct Inner {
    tx: SyncSender<Msg>,
    stats: Arc<ExporterStats>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    closed: AtomicBool,
    shutdown_timeout: Duration,
}

impl SpanSink for Inner {
    fn emit(&self, span: SpanRecord) {
        if self.closed.load(Ordering::Acquire) {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        match self.tx.try_send(Msg::Span(Box::new(span))) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// A running OTLP/HTTP trace exporter. Cloning shares the same exporter.
#[derive(Clone)]
pub struct OtelExporter {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for OtelExporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtelExporter")
            .field("dropped", &self.inner.stats.dropped())
            .field("exported", &self.inner.stats.exported())
            .finish()
    }
}

impl OtelExporter {
    /// Validate `cfg` and start the export thread.
    pub fn start(cfg: &OtelConfig) -> Result<Self, OtelError> {
        validate(cfg)?;
        let target = parse_endpoint(&cfg.endpoint)?;
        let (tx, rx) = mpsc::sync_channel::<Msg>(cfg.queue_capacity);
        let stats = Arc::new(ExporterStats::default());
        let worker = Worker {
            cfg: cfg.clone(),
            target,
            stats: Arc::clone(&stats),
            instance_id: uuid::Uuid::new_v4().to_string(),
        };
        let handle = std::thread::Builder::new()
            .name("entangle-otlp-export".to_owned())
            .spawn(move || worker.run(rx))
            .map_err(|e| OtelError::StartFailed(e.to_string()))?;
        // Shutdown waits for in-flight work: every attempt of a batch.
        let attempts = cfg.max_retries.saturating_add(2);
        let shutdown_timeout = (cfg.request_timeout + cfg.backoff_max).saturating_mul(attempts);
        Ok(Self {
            inner: Arc::new(Inner {
                tx,
                stats,
                thread: Mutex::new(Some(handle)),
                closed: AtomicBool::new(false),
                shutdown_timeout,
            }),
        })
    }

    /// A `tracing` layer that feeds this exporter.
    pub fn layer(&self) -> SpanLayer {
        SpanLayer::new(self.inner.clone())
    }

    /// The exporter's health counters.
    pub fn stats(&self) -> &Arc<ExporterStats> {
        &self.inner.stats
    }

    /// Mirror the exporter's counters into `registry` at every scrape
    /// (`entangle_telemetry_*`).
    pub fn attach_metrics(&self, registry: &crate::Registry) {
        use crate::catalog::names;
        let stats = Arc::clone(&self.inner.stats);
        registry.register_collector(move |r| {
            r.set_counter(
                names::OTLP_DROPPED,
                "Spans dropped because the OTLP export queue was full",
                &[],
                stats.dropped() as f64,
            );
            r.set_counter(
                names::OTLP_EXPORTED,
                "Spans delivered to the OTLP collector",
                &[],
                stats.exported() as f64,
            );
            r.set_counter(
                names::OTLP_FAILED_BATCHES,
                "Span batches abandoned after a permanent error or exhausted retries",
                &[],
                stats.failed_batches() as f64,
            );
        });
    }

    /// Send everything queued so far and wait for it (bounded).
    ///
    /// Returns `false` if the exporter is shut down or did not finish in time.
    pub fn flush(&self) -> bool {
        let (ack_tx, ack_rx) = mpsc::channel();
        if self.inner.tx.send(Msg::Flush(ack_tx)).is_err() {
            return false;
        }
        ack_rx.recv_timeout(self.inner.shutdown_timeout).is_ok()
    }

    /// Stop accepting spans, send what is queued, and stop the thread.
    /// Idempotent; later spans are counted as dropped.
    pub fn shutdown(&self) {
        if self.inner.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let (ack_tx, ack_rx) = mpsc::channel();
        if self.inner.tx.send(Msg::Shutdown(ack_tx)).is_ok() {
            let _ = ack_rx.recv_timeout(self.inner.shutdown_timeout);
        }
        if let Some(handle) = self.inner.thread.lock().take() {
            let _ = handle.join();
        }
    }
}

struct Worker {
    cfg: OtelConfig,
    target: Target,
    stats: Arc<ExporterStats>,
    instance_id: String,
}

impl Worker {
    fn run(self, rx: mpsc::Receiver<Msg>) {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("ENTANGLE-E0654: OTLP exporter runtime failed: {e}");
                return;
            }
        };
        let mut batch: Vec<SpanRecord> = Vec::new();
        let mut deadline = Instant::now() + self.cfg.flush_interval;
        loop {
            let wait = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(wait) {
                Ok(Msg::Span(s)) => {
                    batch.push(*s);
                    if batch.len() >= self.cfg.batch_size {
                        self.send(&rt, &mut batch);
                        deadline = Instant::now() + self.cfg.flush_interval;
                    }
                }
                Ok(Msg::Flush(ack)) => {
                    self.drain(&rx, &mut batch);
                    self.send(&rt, &mut batch);
                    deadline = Instant::now() + self.cfg.flush_interval;
                    let _ = ack.send(());
                }
                Ok(Msg::Shutdown(ack)) => {
                    self.drain(&rx, &mut batch);
                    self.send(&rt, &mut batch);
                    let _ = ack.send(());
                    return;
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.send(&rt, &mut batch);
                    deadline = Instant::now() + self.cfg.flush_interval;
                }
                Err(RecvTimeoutError::Disconnected) => {
                    self.send(&rt, &mut batch);
                    return;
                }
            }
        }
    }

    /// Move every span already queued into `batch`.
    fn drain(&self, rx: &mpsc::Receiver<Msg>, batch: &mut Vec<SpanRecord>) {
        while let Ok(msg) = rx.try_recv() {
            if let Msg::Span(s) = msg {
                batch.push(*s);
            }
        }
    }

    /// Send `batch` in `batch_size` chunks; empties it.
    fn send(&self, rt: &tokio::runtime::Runtime, batch: &mut Vec<SpanRecord>) {
        while !batch.is_empty() {
            let n = batch.len().min(self.cfg.batch_size);
            let chunk: Vec<SpanRecord> = batch.drain(..n).collect();
            let body = encode_batch(&self.cfg.service_name, &self.instance_id, &chunk);
            if rt.block_on(self.post_with_retry(&body)) {
                self.stats.exported.fetch_add(n as u64, Ordering::Relaxed);
            } else {
                self.stats.failed_batches.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    async fn post_with_retry(&self, body: &[u8]) -> bool {
        let mut backoff = self.cfg.backoff_base;
        for attempt in 0..=self.cfg.max_retries {
            let outcome = tokio::time::timeout(self.cfg.request_timeout, self.post(body)).await;
            let retry_after = match outcome {
                Ok(Ok((status, _))) if (200..300).contains(&status) => return true,
                // 429 and 5xx are transient by the OTLP spec; honour the
                // collector's own pacing hint when it sends one.
                Ok(Ok((status, retry_after))) if status == 429 || (500..600).contains(&status) => {
                    retry_after
                }
                // Any other status is permanent: retrying the same bytes
                // cannot change the answer.
                Ok(Ok((status, _))) => {
                    eprintln!(
                        "entangle: OTLP collector rejected a span batch with HTTP {status}; \
                         dropping it"
                    );
                    return false;
                }
                // Connection refused / reset / timeout: the collector may be
                // restarting.
                Ok(Err(_)) | Err(_) => None,
            };
            if attempt == self.cfg.max_retries {
                break;
            }
            self.stats.retries.fetch_add(1, Ordering::Relaxed);
            let sleep = retry_after
                .map(|d| d.min(self.cfg.backoff_max))
                .unwrap_or(backoff);
            tokio::time::sleep(sleep).await;
            backoff = (backoff * 2).min(self.cfg.backoff_max);
        }
        false
    }

    /// One HTTP/1.1 `POST`. Returns the status and any `Retry-After` seconds.
    async fn post(&self, body: &[u8]) -> Result<(u16, Option<Duration>), String> {
        let stream = tokio::net::TcpStream::connect((self.target.host.as_str(), self.target.port))
            .await
            .map_err(|e| format!("connect: {e}"))?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| format!("handshake: {e}"))?;
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });
        let request = Request::post(self.target.path.as_str())
            .header(HOST, self.target.authority.as_str())
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_LENGTH, body.len())
            .header(CONNECTION, "close")
            .header(
                USER_AGENT,
                concat!("entangle-observability/", env!("CARGO_PKG_VERSION")),
            )
            .body(Full::new(Bytes::copy_from_slice(body)))
            .map_err(|e| format!("building request: {e}"))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|e| format!("request: {e}"))?;
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(Duration::from_secs);
        // Drain (a bounded amount of) the body so the connection ends cleanly.
        let mut body = response.into_body();
        let mut seen = 0usize;
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(f) => {
                    seen += f.data_ref().map_or(0, |d| d.len());
                    if seen > 64 * 1024 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        conn_task.abort();
        Ok((status, retry_after))
    }
}

/// Validate `cfg`, start the exporter and return it.
///
/// Install the exporter's [`OtelExporter::layer`] on the global subscriber
/// (see [`crate::init_with_otel`]) and call [`OtelExporter::shutdown`] before
/// exit so the last batch is delivered.
pub fn init(cfg: &OtelConfig) -> Result<OtelExporter, OtelError> {
    OtelExporter::start(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_points_at_the_otlp_http_port() {
        let c = OtelConfig::default();
        assert_eq!(c.endpoint, "http://localhost:4318");
        assert!(!c.endpoint.contains(":4317"), "4317 is OTLP/gRPC");
        assert_eq!(c.service_name, "entangled");
    }

    #[test]
    fn validate_accepts_default_config() {
        validate(&OtelConfig::default()).expect("default must validate");
    }

    #[test]
    fn endpoint_is_split_into_host_port_and_traces_path() {
        let t = parse_endpoint("http://collector.internal:9999/base/").unwrap();
        assert_eq!(t.host, "collector.internal");
        assert_eq!(t.port, 9999);
        assert_eq!(t.path, "/base/v1/traces");
        let t = parse_endpoint("http://localhost").unwrap();
        assert_eq!((t.port, t.path.as_str()), (80, "/v1/traces"));
        let t = parse_endpoint("http://[::1]:4318").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("::1", 4318));
    }

    #[test]
    fn validate_rejects_non_http_scheme() {
        let cfg = OtelConfig {
            endpoint: "grpc://localhost:4317".into(),
            ..OtelConfig::default()
        };
        match validate(&cfg).expect_err("non-http scheme must error") {
            OtelError::InvalidEndpoint { reason, .. } => {
                assert!(reason.contains("http://"), "got reason: {reason}");
            }
            other => panic!("expected InvalidEndpoint, got {other:?}"),
        }
    }

    #[test]
    fn https_is_refused_with_an_explanation() {
        let cfg = OtelConfig {
            endpoint: "https://collector:4318".into(),
            ..OtelConfig::default()
        };
        let err = validate(&cfg).expect_err("https is unsupported");
        assert!(err.to_string().contains("ENTANGLE-E0651"));
        assert!(err.to_string().contains("TLS"), "{err}");
    }

    #[test]
    fn validate_rejects_empty_host() {
        let cfg = OtelConfig {
            endpoint: "http:///some/path".into(),
            ..OtelConfig::default()
        };
        let err = validate(&cfg).expect_err("empty host must error");
        assert!(matches!(err, OtelError::InvalidEndpoint { .. }));
        assert!(err.to_string().contains("ENTANGLE-E0651"));
    }

    #[test]
    fn validate_rejects_query_credentials_and_bad_port() {
        for bad in [
            "http://host:4318/?x=1",
            "http://user:pw@host:4318",
            "http://host:99999",
        ] {
            let cfg = OtelConfig {
                endpoint: bad.into(),
                ..OtelConfig::default()
            };
            assert!(
                matches!(validate(&cfg), Err(OtelError::InvalidEndpoint { .. })),
                "{bad}"
            );
        }
    }

    #[test]
    fn validate_rejects_empty_service_name() {
        let cfg = OtelConfig {
            service_name: "  ".into(),
            ..OtelConfig::default()
        };
        assert!(matches!(validate(&cfg), Err(OtelError::EmptyServiceName)));
    }

    #[test]
    fn validate_rejects_zero_tuning_values() {
        for (cfg, field) in [
            (
                OtelConfig {
                    queue_capacity: 0,
                    ..OtelConfig::default()
                },
                "queue_capacity",
            ),
            (
                OtelConfig {
                    batch_size: 0,
                    ..OtelConfig::default()
                },
                "batch_size",
            ),
            (
                OtelConfig {
                    flush_interval: Duration::ZERO,
                    ..OtelConfig::default()
                },
                "flush_interval",
            ),
            (
                OtelConfig {
                    request_timeout: Duration::ZERO,
                    ..OtelConfig::default()
                },
                "request_timeout",
            ),
        ] {
            match validate(&cfg) {
                Err(OtelError::InvalidSetting { field: f, .. }) => assert_eq!(f, field),
                other => panic!("{field}: {other:?}"),
            }
        }
    }

    #[test]
    fn init_propagates_validation_errors() {
        let cfg = OtelConfig {
            endpoint: "ftp://nope".into(),
            ..OtelConfig::default()
        };
        assert!(matches!(init(&cfg), Err(OtelError::InvalidEndpoint { .. })));
    }
}
