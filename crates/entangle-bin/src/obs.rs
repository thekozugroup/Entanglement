//! The operator read paths over the daemon's in-memory observability
//! stores: `logs/read` (log ring buffers) and `trace/get` (span store).
//!
//! Both stores are filled by the `tracing` subscriber `entangled` installs
//! at startup (`entangle_observability::init_daemon`); nothing here writes to
//! them. Both answers are bounded: a page holds at most
//! [`entangle_observability::logs::MAX_PAGE_LINES`] lines and about
//! [`entangle_observability::logs::MAX_PAGE_BYTES`] bytes, and a long-poll
//! waits at most [`entangle_rpc::methods::LOGS_MAX_WAIT_MS`].
//!
//! Errors are `-32602` (a bad parameter or an unknown source, with an
//! `ENTANGLE-E068x` code in the message) or `-32000` (no such trace).

use crate::state::DaemonState;
use entangle_observability::context::{AttrValue, SpanKind, SpanRecord, SpanStatus};
use entangle_observability::logs::{
    resolve_source, LogLevel, LogLine, LogQuery, LogSource, MAX_PAGE_LINES,
};
use entangle_observability::traces::TraceView;
use entangle_observability::QueryError;
use entangle_rpc::methods::{
    LogLineWire, LogsReadParams, LogsReadResult, SpanEventWire, SpanWire, TraceGetParams,
    TraceGetResult, TraceWire, LOGS_MAX_WAIT_MS,
};
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Lines per page when the caller does not say.
pub const DEFAULT_LINES: usize = 200;

#[derive(Serialize)]
struct Resp<'a, T: Serialize> {
    jsonrpc: &'static str,
    id: &'a serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrBody>,
}

#[derive(Serialize)]
struct ErrBody {
    code: i32,
    message: String,
}

fn ok<T: Serialize>(id: serde_json::Value, result: T) -> String {
    serde_json::to_string(&Resp {
        jsonrpc: "2.0",
        id: &id,
        result: Some(result),
        error: None,
    })
    .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"internal serialization error"}}"#.to_owned())
}

fn err(id: serde_json::Value, code: i32, message: String) -> String {
    serde_json::to_string(&Resp::<serde_json::Value> {
        jsonrpc: "2.0",
        id: &id,
        result: None,
        error: Some(ErrBody { code, message }),
    })
    .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"internal serialization error"}}"#.to_owned())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn wire_line(l: LogLine) -> LogLineWire {
    LogLineWire {
        seq: l.seq,
        unix_ms: l.unix_ms,
        level: l.level.as_str().to_owned(),
        target: l.target,
        event: l.event,
        message: l.message,
        fields: l.fields,
    }
}

/// `logs/read`: tail, page, or long-poll one log buffer.
pub async fn handle_logs_read(
    id: serde_json::Value,
    params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> String {
    let p: LogsReadParams = match serde_json::from_value(params) {
        Ok(v) => v,
        Err(e) => return err(id, -32602, format!("invalid params: {e}")),
    };
    let min_level = match p.level.as_deref() {
        None => LogLevel::Trace,
        Some(l) => match LogLevel::parse(l) {
            Some(l) => l,
            None => {
                return err(
                    id,
                    -32602,
                    QueryError::InvalidQuery(format!(
                        "level '{l}' is not one of trace, debug, info, warn, error"
                    ))
                    .to_string(),
                )
            }
        },
    };
    if p.limit == Some(0) {
        return err(
            id,
            -32602,
            QueryError::InvalidQuery("limit must be at least 1".to_owned()).to_string(),
        );
    }
    let mut known: Vec<String> = state
        .kernel
        .list_plugins()
        .iter()
        .map(ToString::to_string)
        .collect();
    known.extend(state.logs.plugin_ids());
    let source = match resolve_source(&p.source, known) {
        Ok(s) => s,
        Err(e) => return err(id, -32602, e.to_string()),
    };
    let source_name = match &source {
        LogSource::Subsystem(s) => s.name().to_owned(),
        LogSource::Plugin(p) => p.clone(),
    };
    let query = LogQuery {
        source,
        after: p.after,
        min_level,
        filter: p.filter.filter(|f| !f.is_empty()),
        since_unix_ms: p.since_ms.map(|ms| now_ms().saturating_sub(ms)),
        limit: p.limit.unwrap_or(DEFAULT_LINES).min(MAX_PAGE_LINES),
    };

    // Subscribe before the first read so a line stored between the read and
    // the wait still wakes us.
    let mut rx = state.logs.subscribe();
    let wait = Duration::from_millis(p.wait_ms.unwrap_or(0).min(LOGS_MAX_WAIT_MS));
    let deadline = tokio::time::Instant::now() + wait;
    let page = loop {
        let page = state.logs.read(&query);
        if !page.lines.is_empty()
            || page.truncated
            || query.after.is_none()
            || wait.is_zero()
            || tokio::time::Instant::now() >= deadline
        {
            break page;
        }
        match tokio::time::timeout_at(deadline, rx.changed()).await {
            Ok(Ok(())) => continue,
            // Deadline passed (or the hub is gone): answer with what there is.
            _ => break state.logs.read(&query),
        }
    };
    ok(
        id,
        LogsReadResult {
            source: source_name,
            lines: page.lines.into_iter().map(wire_line).collect(),
            next_cursor: page.next_cursor,
            more: page.more,
            truncated: page.truncated,
        },
    )
}

fn hex(bytes: &[u8]) -> String {
    entangle_observability::context::hex_string(bytes)
}

fn unix_ms(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn attr_text(v: &AttrValue) -> String {
    match v {
        AttrValue::Str(s) => s.clone(),
        AttrValue::Int(i) => i.to_string(),
        AttrValue::Double(d) => d.to_string(),
        AttrValue::Bool(b) => b.to_string(),
    }
}

fn attrs(a: &[(String, AttrValue)]) -> Vec<(String, String)> {
    a.iter().map(|(k, v)| (k.clone(), attr_text(v))).collect()
}

fn wire_span(s: &SpanRecord) -> SpanWire {
    let (status, status_message) = match &s.status {
        SpanStatus::Unset => ("unset", None),
        SpanStatus::Ok => ("ok", None),
        SpanStatus::Error(m) => ("error", Some(m.clone())),
    };
    SpanWire {
        span_id: hex(&s.span_id),
        parent_span_id: s.parent_span_id.map(|p| hex(&p)),
        name: s.name.clone(),
        kind: match s.kind {
            SpanKind::Internal => "internal",
            SpanKind::Server => "server",
            SpanKind::Client => "client",
        }
        .to_owned(),
        start_unix_nanos: u64::try_from(SpanRecord::unix_nanos(s.start)).unwrap_or(u64::MAX),
        duration_us: s
            .end
            .duration_since(s.start)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0),
        status: status.to_owned(),
        status_message,
        attributes: attrs(&s.attributes),
        events: s
            .events
            .iter()
            .map(|e| SpanEventWire {
                unix_ms: unix_ms(e.time),
                name: e.name.clone(),
                attributes: attrs(&e.attributes),
            })
            .collect(),
    }
}

fn wire_trace(t: TraceView) -> TraceWire {
    TraceWire {
        trace_id: hex(&t.trace_id),
        spans: t.spans.iter().map(wire_span).collect(),
        dropped_spans: t.dropped_spans,
        remote_hints: t.remote_hints(),
    }
}

/// A 32-hex-digit trace id, as bytes.
fn parse_trace_id(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// `trace/get`: the spans recorded for a task id or a trace id.
pub fn handle_trace_get(
    id: serde_json::Value,
    params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> String {
    let p: TraceGetParams = match serde_json::from_value(params) {
        Ok(v) => v,
        Err(e) => return err(id, -32602, format!("invalid params: {e}")),
    };
    let given = p.id.trim();
    // A task id is a UUID (32 hex digits, dashes optional) and so is the
    // same shape as a trace id: try it as a task first, then as a trace.
    let plain: String = given.chars().filter(|c| *c != '-').collect();
    if plain.len() != 32 || !plain.bytes().all(|b| b.is_ascii_hexdigit()) {
        return err(
            id,
            -32602,
            QueryError::InvalidTraceId(given.to_owned()).to_string(),
        );
    }
    let mut traces = state.traces.by_task(&plain);
    if traces.is_empty() {
        if let Some(t) =
            parse_trace_id(&plain.to_ascii_lowercase()).and_then(|t| state.traces.by_trace(&t))
        {
            traces.push(t);
        }
    }
    if traces.is_empty() {
        return err(
            id,
            -32000,
            QueryError::NoSuchTrace {
                what: "task or trace",
                id: given.to_owned(),
            }
            .to_string(),
        );
    }
    ok(
        id,
        TraceGetResult {
            id: given.to_owned(),
            traces: traces.into_iter().map(wire_trace).collect(),
        },
    )
}
