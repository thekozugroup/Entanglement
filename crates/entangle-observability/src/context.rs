//! W3C trace context and the span-recording `tracing` layer.
//!
//! [`SpanLayer`] turns `tracing` spans into [`SpanRecord`]s with OpenTelemetry
//! shaped ids (128-bit trace id, 64-bit span id, parent span id) and hands
//! each finished span to a [`SpanSink`] (the OTLP exporter in
//! [`crate::otel`], or a test double). It is independent of any network code.
//!
//! # Propagation
//!
//! * [`current_traceparent`] renders the current span as a W3C
//!   `traceparent` header value for an outgoing request.
//! * [`set_remote_parent`] makes a freshly created span a child of a remote
//!   `traceparent`: it adopts the remote trace id and records the remote span
//!   as its parent. Call it right after creating the span, before creating
//!   child spans.
//!
//! A `traceparent` is **never** used for authorization or any decision other
//! than "which trace does this span belong to": anything a peer sends is
//! untrusted, and a malformed value is simply ignored.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::{LookupSpan, Registry as SubscriberRegistry, SpanData};
use tracing_subscriber::Layer;

/// Longest accepted `traceparent` header value (version 00 is 55 bytes; the
/// spec lets future versions append fields).
pub const MAX_TRACEPARENT_LEN: usize = 256;

/// Most attributes kept per span or event; the rest are dropped.
pub const MAX_ATTRIBUTES: usize = 64;
/// Most events kept per span.
pub const MAX_EVENTS: usize = 32;
/// Longest attribute string value kept, in bytes.
pub const MAX_ATTRIBUTE_BYTES: usize = 1024;

// ── trace context ────────────────────────────────────────────────────────────

/// A W3C trace context: which trace, which span, sampled or not.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TraceContext {
    /// 128-bit trace id (never all zero).
    pub trace_id: [u8; 16],
    /// 64-bit span id (never all zero).
    pub span_id: [u8; 8],
    /// The `sampled` trace flag.
    pub sampled: bool,
}

/// Why a `traceparent` was rejected.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TraceparentError {
    /// Longer than [`MAX_TRACEPARENT_LEN`] or not `00-<32>-<16>-<2>`.
    Malformed,
    /// Version `ff` is reserved by the spec.
    ReservedVersion,
    /// An all-zero trace id or span id.
    ZeroId,
}

impl std::fmt::Display for TraceparentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed traceparent",
            Self::ReservedVersion => "traceparent version ff is reserved",
            Self::ZeroId => "traceparent has an all-zero id",
        })
    }
}

impl std::error::Error for TraceparentError {}

impl TraceContext {
    /// Parse a `traceparent` header value.
    ///
    /// Accepts version `00` exactly; a higher version (other than the
    /// reserved `ff`) is read as far as the version-00 fields, as the spec
    /// requires of forward-compatible parsers. Hex must be lowercase.
    pub fn parse(value: &str) -> Result<Self, TraceparentError> {
        if value.len() > MAX_TRACEPARENT_LEN || !value.is_ascii() {
            return Err(TraceparentError::Malformed);
        }
        let mut parts = value.split('-');
        let (Some(version), Some(trace), Some(span), Some(flags)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(TraceparentError::Malformed);
        };
        if version.len() != 2 || !is_lower_hex(version) {
            return Err(TraceparentError::Malformed);
        }
        if version == "ff" {
            return Err(TraceparentError::ReservedVersion);
        }
        // Version 00 has exactly four fields; later versions may append more.
        if version == "00" && parts.next().is_some() {
            return Err(TraceparentError::Malformed);
        }
        if trace.len() != 32 || span.len() != 16 || flags.len() != 2 {
            return Err(TraceparentError::Malformed);
        }
        if !is_lower_hex(trace) || !is_lower_hex(span) || !is_lower_hex(flags) {
            return Err(TraceparentError::Malformed);
        }
        let mut trace_id = [0u8; 16];
        let mut span_id = [0u8; 8];
        decode_hex(trace, &mut trace_id);
        decode_hex(span, &mut span_id);
        if trace_id == [0; 16] || span_id == [0; 8] {
            return Err(TraceparentError::ZeroId);
        }
        let mut flag = [0u8; 1];
        decode_hex(flags, &mut flag);
        Ok(Self {
            trace_id,
            span_id,
            sampled: flag[0] & 1 == 1,
        })
    }

    /// Render as a version-00 `traceparent` value.
    pub fn to_traceparent(&self) -> String {
        format!(
            "00-{}-{}-{}",
            hex_string(&self.trace_id),
            hex_string(&self.span_id),
            if self.sampled { "01" } else { "00" }
        )
    }
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn decode_hex(s: &str, out: &mut [u8]) {
    // Callers validated length and alphabet, so every pair is two hex digits.
    for (i, pair) in s.as_bytes().chunks(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16).unwrap_or(0) as u8;
        let lo = (pair[1] as char).to_digit(16).unwrap_or(0) as u8;
        out[i] = (hi << 4) | lo;
    }
}

/// Lowercase hex of `bytes`.
pub fn hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String cannot fail.
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn random_trace_id() -> [u8; 16] {
    *uuid::Uuid::new_v4().as_bytes()
}

fn random_span_id() -> [u8; 8] {
    let b = *uuid::Uuid::new_v4().as_bytes();
    let mut id = [0u8; 8];
    id.copy_from_slice(&b[..8]);
    // An all-zero span id is invalid; the chance is 2^-64, but be exact.
    if id == [0; 8] {
        id[7] = 1;
    }
    id
}

// ── span records ─────────────────────────────────────────────────────────────

/// An attribute value.
#[derive(Clone, Debug, PartialEq)]
pub enum AttrValue {
    /// UTF-8 text.
    Str(String),
    /// Signed integer.
    Int(i64),
    /// Floating point.
    Double(f64),
    /// Boolean.
    Bool(bool),
}

/// OpenTelemetry span kind.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SpanKind {
    /// Internal operation (the default).
    Internal,
    /// Handling a request from a remote caller.
    Server,
    /// Making a request to a remote service.
    Client,
}

impl SpanKind {
    /// The OTLP numeric `SpanKind`.
    pub const fn otlp(self) -> u8 {
        match self {
            Self::Internal => 1,
            Self::Server => 2,
            Self::Client => 3,
        }
    }
}

/// A point-in-time annotation on a span.
#[derive(Clone, Debug, PartialEq)]
pub struct SpanEvent {
    /// Wall-clock time of the event.
    pub time: SystemTime,
    /// The event's message.
    pub name: String,
    /// The event's fields.
    pub attributes: Vec<(String, AttrValue)>,
}

/// Final status of a span.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpanStatus {
    /// Nothing recorded.
    Unset,
    /// Recorded `otel.status_code = "OK"`.
    Ok,
    /// An ERROR-level event occurred inside the span, or
    /// `otel.status_code = "ERROR"` was recorded.
    Error(String),
}

/// A finished span, ready to export.
#[derive(Clone, Debug, PartialEq)]
pub struct SpanRecord {
    /// Trace this span belongs to.
    pub trace_id: [u8; 16],
    /// This span's id.
    pub span_id: [u8; 8],
    /// Parent span id (local or remote), if any.
    pub parent_span_id: Option<[u8; 8]>,
    /// Span name (the `tracing` span name).
    pub name: String,
    /// Span kind.
    pub kind: SpanKind,
    /// Start time.
    pub start: SystemTime,
    /// End time (`start` plus the monotonic elapsed time).
    pub end: SystemTime,
    /// Recorded fields, in recording order.
    pub attributes: Vec<(String, AttrValue)>,
    /// WARN/ERROR events that occurred inside the span.
    pub events: Vec<SpanEvent>,
    /// Final status.
    pub status: SpanStatus,
}

impl SpanRecord {
    /// Nanoseconds since the Unix epoch for `t` (0 before the epoch).
    pub fn unix_nanos(t: SystemTime) -> u128 {
        t.duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos()
    }
}

/// Receives each finished span.
pub trait SpanSink: Send + Sync + 'static {
    /// Called once per span, when it closes. Must not block.
    fn emit(&self, span: SpanRecord);
}

// ── per-span state kept in the registry's extensions ─────────────────────────

struct SpanState {
    trace_id: [u8; 16],
    span_id: [u8; 8],
    parent_span_id: Option<[u8; 8]>,
    kind: SpanKind,
    start: SystemTime,
    started: Instant,
    attributes: Vec<(String, AttrValue)>,
    events: Vec<SpanEvent>,
    status: SpanStatus,
}

impl SpanState {
    fn push_attr(&mut self, key: &str, value: AttrValue) {
        match key {
            // Conventional `tracing-opentelemetry` pseudo-fields.
            "otel.kind" => {
                if let AttrValue::Str(s) = &value {
                    self.kind = match s.to_ascii_lowercase().as_str() {
                        "server" => SpanKind::Server,
                        "client" => SpanKind::Client,
                        _ => SpanKind::Internal,
                    };
                }
            }
            "otel.status_code" => {
                if let AttrValue::Str(s) = &value {
                    match s.to_ascii_uppercase().as_str() {
                        "OK" => {
                            if self.status == SpanStatus::Unset {
                                self.status = SpanStatus::Ok;
                            }
                        }
                        "ERROR" => {
                            if !matches!(self.status, SpanStatus::Error(_)) {
                                self.status = SpanStatus::Error(String::new());
                            }
                        }
                        _ => {}
                    }
                }
            }
            "otel.status_message" => {
                if let (AttrValue::Str(s), SpanStatus::Error(m)) = (&value, &mut self.status) {
                    *m = s.clone();
                }
            }
            _ => {
                if let Some(slot) = self.attributes.iter_mut().find(|(k, _)| k == key) {
                    slot.1 = value;
                } else if self.attributes.len() < MAX_ATTRIBUTES {
                    self.attributes.push((key.to_owned(), value));
                }
            }
        }
    }
}

/// Collects `tracing` fields into attributes.
#[derive(Default)]
struct AttrVisitor {
    fields: Vec<(String, AttrValue)>,
    message: Option<String>,
}

impl AttrVisitor {
    fn push(&mut self, field: &Field, value: AttrValue) {
        if field.name() == "message" {
            if let AttrValue::Str(s) = value {
                self.message = Some(s);
            }
        } else {
            self.fields.push((field.name().to_owned(), value));
        }
    }
}

fn clip(mut s: String) -> String {
    if s.len() > MAX_ATTRIBUTE_BYTES {
        let mut cut = MAX_ATTRIBUTE_BYTES;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    s
}

impl Visit for AttrVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field, AttrValue::Str(clip(value.to_owned())));
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push(field, AttrValue::Int(value));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        match i64::try_from(value) {
            Ok(v) => self.push(field, AttrValue::Int(v)),
            Err(_) => self.push(field, AttrValue::Str(value.to_string())),
        }
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.push(field, AttrValue::Double(value));
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push(field, AttrValue::Bool(value));
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.push(field, AttrValue::Str(clip(format!("{value:?}"))));
    }
}

// ── the layer ────────────────────────────────────────────────────────────────

/// A `tracing` layer that records spans into a [`SpanSink`].
///
/// Install it on a [`tracing_subscriber::Registry`] (the layer stores its
/// per-span state in the registry's span extensions, so the propagation
/// helpers need that registry underneath).
#[derive(Clone)]
pub struct SpanLayer {
    sink: Arc<dyn SpanSink>,
}

impl SpanLayer {
    /// A layer delivering finished spans to `sink`.
    pub fn new(sink: Arc<dyn SpanSink>) -> Self {
        Self { sink }
    }
}

impl<S> Layer<S> for SpanLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let (trace_id, parent_span_id) = match span.parent() {
            Some(parent) => match parent.extensions().get::<SpanState>() {
                Some(p) => (p.trace_id, Some(p.span_id)),
                None => (random_trace_id(), None),
            },
            None => (random_trace_id(), None),
        };
        let mut state = SpanState {
            trace_id,
            span_id: random_span_id(),
            parent_span_id,
            kind: SpanKind::Internal,
            start: SystemTime::now(),
            started: Instant::now(),
            attributes: Vec::new(),
            events: Vec::new(),
            status: SpanStatus::Unset,
        };
        let mut visitor = AttrVisitor::default();
        attrs.record(&mut visitor);
        for (k, v) in visitor.fields {
            state.push_attr(&k, v);
        }
        span.extensions_mut().insert(state);
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut ext = span.extensions_mut();
        let Some(state) = ext.get_mut::<SpanState>() else {
            return;
        };
        let mut visitor = AttrVisitor::default();
        values.record(&mut visitor);
        for (k, v) in visitor.fields {
            state.push_attr(&k, v);
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        // Only problems become span events; INFO/DEBUG chatter would swamp
        // the trace.
        if *event.metadata().level() > Level::WARN {
            return;
        }
        let Some(span) = ctx.event_span(event) else {
            return;
        };
        let mut ext = span.extensions_mut();
        let Some(state) = ext.get_mut::<SpanState>() else {
            return;
        };
        let mut visitor = AttrVisitor::default();
        event.record(&mut visitor);
        let message = visitor
            .message
            .clone()
            .unwrap_or_else(|| event.metadata().name().to_owned());
        if *event.metadata().level() == Level::ERROR
            && !matches!(state.status, SpanStatus::Error(_))
        {
            state.status = SpanStatus::Error(clip(message.clone()));
        }
        if state.events.len() < MAX_EVENTS {
            visitor.fields.truncate(MAX_ATTRIBUTES);
            state.events.push(SpanEvent {
                time: SystemTime::now(),
                name: clip(message),
                attributes: visitor.fields,
            });
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else { return };
        let name = span.name().to_owned();
        let Some(state) = span.extensions_mut().remove::<SpanState>() else {
            return;
        };
        let end = state.start + state.started.elapsed();
        self.sink.emit(SpanRecord {
            trace_id: state.trace_id,
            span_id: state.span_id,
            parent_span_id: state.parent_span_id,
            name,
            kind: state.kind,
            start: state.start,
            end,
            attributes: state.attributes,
            events: state.events,
            status: state.status,
        });
    }
}

// ── propagation helpers ──────────────────────────────────────────────────────

fn with_state<R>(span: &tracing::Span, f: impl FnOnce(&mut SpanState) -> R) -> Option<R> {
    span.with_subscriber(|(id, dispatch)| {
        let registry = dispatch.downcast_ref::<SubscriberRegistry>()?;
        let data = registry.span_data(id)?;
        let mut ext = data.extensions_mut();
        ext.get_mut::<SpanState>().map(f)
    })
    .flatten()
}

/// The trace context of `span`, if a [`SpanLayer`] is recording it.
pub fn context_of(span: &tracing::Span) -> Option<TraceContext> {
    with_state(span, |s| TraceContext {
        trace_id: s.trace_id,
        span_id: s.span_id,
        sampled: true,
    })
}

/// The W3C `traceparent` value for `span`, or `None` when no [`SpanLayer`] is
/// recording it (tracing export is off, or the span is filtered out).
pub fn traceparent_of(span: &tracing::Span) -> Option<String> {
    context_of(span).map(|c| c.to_traceparent())
}

/// The W3C `traceparent` value for the current span.
pub fn current_traceparent() -> Option<String> {
    traceparent_of(&tracing::Span::current())
}

/// Make `span` a child of the remote span named by `traceparent`.
///
/// Returns `true` when applied. A malformed or unsampled `traceparent`, or a
/// span no [`SpanLayer`] is recording, returns `false` and leaves the span as
/// the root of its own trace — peers cannot make a worker fail by sending
/// garbage. Call this immediately after creating `span`, before it has
/// children, since children copy the trace id at creation.
pub fn set_remote_parent(span: &tracing::Span, traceparent: &str) -> bool {
    let Ok(remote) = TraceContext::parse(traceparent) else {
        return false;
    };
    if !remote.sampled {
        return false;
    }
    with_state(span, |s| {
        s.trace_id = remote.trace_id;
        s.parent_span_id = Some(remote.span_id);
    })
    .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use tracing::info_span;
    use tracing_subscriber::prelude::*;

    #[derive(Default)]
    struct Collect(Mutex<Vec<SpanRecord>>);
    impl SpanSink for Collect {
        fn emit(&self, span: SpanRecord) {
            self.0.lock().push(span);
        }
    }

    fn with_layer<R>(f: impl FnOnce() -> R) -> (R, Vec<SpanRecord>) {
        let sink = Arc::new(Collect::default());
        let sub = tracing_subscriber::registry().with(SpanLayer::new(sink.clone()));
        let r = tracing::subscriber::with_default(sub, f);
        let spans = sink.0.lock().clone();
        (r, spans)
    }

    #[test]
    fn traceparent_round_trips_and_validates() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let ctx = TraceContext::parse(tp).unwrap();
        assert_eq!(ctx.to_traceparent(), tp);
        assert!(ctx.sampled);
        assert!(
            !TraceContext::parse(&tp.replace("-01", "-00"))
                .unwrap()
                .sampled
        );

        for bad in [
            "",
            "garbage",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e47-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0g",
        ] {
            assert_eq!(
                TraceContext::parse(bad),
                Err(TraceparentError::Malformed),
                "{bad}"
            );
        }
        assert_eq!(
            TraceContext::parse("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
            Err(TraceparentError::ReservedVersion)
        );
        assert_eq!(
            TraceContext::parse("00-00000000000000000000000000000000-00f067aa0ba902b7-01"),
            Err(TraceparentError::ZeroId)
        );
        assert_eq!(
            TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01"),
            Err(TraceparentError::ZeroId)
        );
        // A future version may append fields.
        assert!(TraceContext::parse(
            "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-more"
        )
        .is_ok());
        assert_eq!(
            TraceContext::parse(&"0".repeat(MAX_TRACEPARENT_LEN + 1)),
            Err(TraceparentError::Malformed)
        );
    }

    #[test]
    fn nested_spans_share_a_trace_and_link_to_their_parent() {
        let (_, spans) = with_layer(|| {
            let outer = info_span!("outer", job = "a", n = 3u64);
            let _o = outer.enter();
            let inner = info_span!("inner");
            let _i = inner.enter();
        });
        assert_eq!(spans.len(), 2);
        let inner = spans.iter().find(|s| s.name == "inner").unwrap();
        let outer = spans.iter().find(|s| s.name == "outer").unwrap();
        assert_eq!(inner.trace_id, outer.trace_id);
        assert_eq!(inner.parent_span_id, Some(outer.span_id));
        assert_eq!(outer.parent_span_id, None);
        assert_ne!(inner.span_id, outer.span_id);
        assert!(outer
            .attributes
            .contains(&("job".to_owned(), AttrValue::Str("a".into()))));
        assert!(outer
            .attributes
            .contains(&("n".to_owned(), AttrValue::Int(3))));
        assert!(outer.end >= outer.start);
    }

    #[test]
    fn remote_parent_adopts_trace_id_and_parent_span() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let (applied, spans) = with_layer(|| {
            let span = info_span!("worker");
            let applied = set_remote_parent(&span, tp);
            let _g = span.enter();
            let child = info_span!("child");
            drop(child);
            // The outgoing header from inside continues the same trace.
            let out = current_traceparent().unwrap();
            assert!(
                out.starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-"),
                "{out}"
            );
            assert_ne!(out, tp);
            applied
        });
        assert!(applied);
        let worker = spans.iter().find(|s| s.name == "worker").unwrap();
        let child = spans.iter().find(|s| s.name == "child").unwrap();
        assert_eq!(
            hex_string(&worker.trace_id),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        assert_eq!(
            worker.parent_span_id.map(|p| hex_string(&p)).as_deref(),
            Some("00f067aa0ba902b7")
        );
        assert_eq!(child.trace_id, worker.trace_id);
        assert_eq!(child.parent_span_id, Some(worker.span_id));
    }

    #[test]
    fn garbage_or_unsampled_remote_parent_is_ignored() {
        let (results, spans) = with_layer(|| {
            let span = info_span!("worker");
            [
                set_remote_parent(&span, "nonsense"),
                set_remote_parent(
                    &span,
                    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00",
                ),
            ]
        });
        assert_eq!(results, [false, false]);
        assert_eq!(spans[0].parent_span_id, None);
    }

    #[test]
    fn without_the_layer_there_is_no_traceparent() {
        let sub = tracing_subscriber::registry();
        tracing::subscriber::with_default(sub, || {
            let span = info_span!("x");
            let _g = span.enter();
            assert_eq!(current_traceparent(), None);
            assert!(!set_remote_parent(
                &span,
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
            ));
        });
    }

    #[test]
    fn error_events_set_status_and_warnings_become_span_events() {
        let (_, spans) = with_layer(|| {
            let span = info_span!("op", otel.kind = "client");
            let _g = span.enter();
            tracing::warn!(code = 7u64, "careful");
            tracing::error!("it broke");
            tracing::info!("not recorded");
        });
        let s = &spans[0];
        assert_eq!(s.kind, SpanKind::Client);
        assert_eq!(s.status, SpanStatus::Error("it broke".into()));
        let names: Vec<_> = s.events.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["careful", "it broke"]);
        assert_eq!(
            s.events[0].attributes,
            vec![("code".to_owned(), AttrValue::Int(7))]
        );
    }

    #[test]
    fn attribute_values_are_clipped() {
        let big = "é".repeat(MAX_ATTRIBUTE_BYTES);
        let (_, spans) = with_layer(|| {
            let _s = info_span!("big", v = %big).entered();
        });
        match &spans[0].attributes[0].1 {
            AttrValue::Str(s) => {
                assert!(s.len() <= MAX_ATTRIBUTE_BYTES);
                assert!(s.chars().all(|c| c == 'é'));
            }
            other => panic!("{other:?}"),
        }
    }
}
