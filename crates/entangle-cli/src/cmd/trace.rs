//! `entangle trace task <id>` — the spans the daemon recorded for a task
//! (spec §9.6).
//!
//! The daemon keeps a bounded, in-memory store of recent spans (no collector
//! needed). This command fetches the spans of one task, or of one trace when
//! given a trace id, and prints the span tree with durations, status and key
//! attributes. The task id is the `Task:` line `entangle compute dispatch`
//! prints. Work a peer executed is recorded on that peer: the output says so
//! when parts of the trace live on other nodes.
//!
//! ```text
//! Trace 4bf92f3577b34da6a3ce929d0e0e4736  (3 spans)
//! task.dispatch  12.4ms  plugin=… policy=none
//! └─ remote.dispatch  11.9ms  client  peer=… transport=iroh
//!    └─ remote.task.execute  8.10ms  server  peer=…
//! ```

use clap::{Args, Subcommand};
use entangle_rpc::methods::{SpanWire, TraceGetResult, TraceWire};
use entangle_rpc::{Client as RpcClient, RpcError};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use super::logs::escape_controls;
use crate::daemon_not_running_error;

/// Attributes shown per span in the tree.
const MAX_ATTRS: usize = 8;
/// Longest attribute value shown.
const MAX_VALUE: usize = 80;

/// Arguments of `entangle trace`.
#[derive(Args)]
pub struct TraceArgs {
    #[command(subcommand)]
    pub cmd: TraceCmd,
}

/// `entangle trace` subcommands.
#[derive(Subcommand)]
pub enum TraceCmd {
    /// Show the recorded span tree of a task.
    Task {
        /// The task id (a UUID, as printed by `entangle compute dispatch`),
        /// or a 32-hex-digit trace id.
        id: String,
        /// Emit the daemon's answer as JSON.
        #[arg(long)]
        json: bool,
    },
}

/// Run `entangle trace`.
pub async fn run(a: TraceArgs) -> anyhow::Result<()> {
    run_with(a, RpcClient::new(RpcClient::default_socket())).await
}

pub(crate) async fn run_with(a: TraceArgs, client: RpcClient) -> anyhow::Result<()> {
    match a.cmd {
        TraceCmd::Task { id, json } => {
            let r = client.trace_get(&id).await.map_err(|e| match e {
                RpcError::DaemonNotRunning(_) => daemon_not_running_error(),
                RpcError::Rpc { message, .. } => anyhow::anyhow!(message),
                e => e.into(),
            })?;
            if json {
                println!("{}", serde_json::to_string_pretty(&r)?);
            } else {
                print!("{}", render(&r));
            }
            Ok(())
        }
    }
}

/// `850µs`, `12.4ms`, `1.20s`.
pub fn format_duration_us(us: u64) -> String {
    if us < 1_000 {
        format!("{us}µs")
    } else if us < 1_000_000 {
        format!("{:.1}ms", us as f64 / 1_000.0)
    } else {
        format!("{:.2}s", us as f64 / 1_000_000.0)
    }
}

/// `v` cut to [`MAX_VALUE`] characters, its control characters escaped
/// (event names, status messages and attribute values can carry text a
/// plugin chose; see [`escape_controls`]).
fn short(v: &str) -> String {
    if v.chars().count() > MAX_VALUE {
        let cut: String = v.chars().take(MAX_VALUE).collect();
        format!("{}…", escape_controls(&cut))
    } else {
        escape_controls(v).into_owned()
    }
}

/// The human-readable form of a `trace/get` answer.
pub fn render(r: &TraceGetResult) -> String {
    let mut out = String::new();
    for (i, t) in r.traces.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        render_trace(&mut out, t, &r.id);
    }
    out
}

fn render_trace(out: &mut String, t: &TraceWire, asked: &str) {
    let _ = writeln!(
        out,
        "Trace {}  ({} spans)  for {}",
        escape_controls(&t.trace_id),
        t.spans.len(),
        escape_controls(asked)
    );
    let ids: HashSet<&str> = t.spans.iter().map(|s| s.span_id.as_str()).collect();
    let mut children: HashMap<&str, Vec<&SpanWire>> = HashMap::new();
    let mut roots: Vec<&SpanWire> = Vec::new();
    for s in &t.spans {
        match s.parent_span_id.as_deref() {
            Some(p) if ids.contains(p) && p != s.span_id => children.entry(p).or_default().push(s),
            _ => roots.push(s),
        }
    }
    let by_start = |a: &&SpanWire, b: &&SpanWire| {
        a.start_unix_nanos
            .cmp(&b.start_unix_nanos)
            .then(a.span_id.cmp(&b.span_id))
    };
    roots.sort_by(by_start);
    for v in children.values_mut() {
        v.sort_by(by_start);
    }
    let mut seen = HashSet::new();
    let n = roots.len();
    for (i, r) in roots.iter().enumerate() {
        write_span(out, r, "", i + 1 == n, true, &children, &mut seen);
    }
    if t.dropped_spans > 0 {
        let _ = writeln!(
            out,
            "note: {} more spans of this trace were not kept (per-trace limit)",
            t.dropped_spans
        );
    }
    for h in &t.remote_hints {
        let _ = writeln!(out, "note: {}", escape_controls(h));
    }
}

fn write_span<'a>(
    out: &mut String,
    s: &'a SpanWire,
    prefix: &str,
    last: bool,
    root: bool,
    children: &HashMap<&str, Vec<&'a SpanWire>>,
    seen: &mut HashSet<&'a str>,
) {
    if !seen.insert(s.span_id.as_str()) {
        return;
    }
    let branch = if root {
        ""
    } else if last {
        "└─ "
    } else {
        "├─ "
    };
    let mut line = format!(
        "{prefix}{branch}{}  {}",
        escape_controls(&s.name),
        format_duration_us(s.duration_us)
    );
    if s.kind != "internal" {
        let _ = write!(line, "  {}", escape_controls(&s.kind));
    }
    if s.status == "error" {
        let _ = write!(
            line,
            "  ERROR{}",
            s.status_message
                .as_deref()
                .map(|m| format!(": {}", short(m)))
                .unwrap_or_default()
        );
    } else if s.status == "ok" {
        line.push_str("  ok");
    }
    let shown = s.attributes.iter().filter(|(k, _)| k != "otel.kind");
    for (k, v) in shown.clone().take(MAX_ATTRS) {
        let _ = write!(line, "  {}={}", escape_controls(k), short(v));
    }
    let hidden = shown.count().saturating_sub(MAX_ATTRS);
    if hidden > 0 {
        let _ = write!(line, "  (+{hidden} more)");
    }
    out.push_str(&line);
    out.push('\n');
    let child_prefix = if root {
        String::new()
    } else {
        format!("{prefix}{}", if last { "   " } else { "│  " })
    };
    for e in &s.events {
        let _ = writeln!(out, "{child_prefix}   ! {}", short(&e.name));
    }
    if let Some(kids) = children.get(s.span_id.as_str()) {
        let n = kids.len();
        for (i, k) in kids.iter().enumerate() {
            write_span(out, k, &child_prefix, i + 1 == n, false, children, seen);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(id: &str, parent: Option<&str>, name: &str, start: u64, us: u64) -> SpanWire {
        SpanWire {
            span_id: id.into(),
            parent_span_id: parent.map(Into::into),
            name: name.into(),
            kind: "internal".into(),
            start_unix_nanos: start,
            duration_us: us,
            status: "unset".into(),
            status_message: None,
            attributes: vec![],
            events: vec![],
        }
    }

    #[test]
    fn durations_scale() {
        assert_eq!(format_duration_us(850), "850µs");
        assert_eq!(format_duration_us(12_400), "12.4ms");
        assert_eq!(format_duration_us(1_200_000), "1.20s");
    }

    #[test]
    fn the_tree_nests_by_parent_and_orders_siblings_by_start() {
        let mut client = span("b", Some("a"), "remote.dispatch", 2, 11_900);
        client.kind = "client".into();
        client.attributes = vec![
            ("peer".into(), "ab12".into()),
            ("transport".into(), "iroh".into()),
        ];
        let mut bad = span("e", Some("a"), "integrity.check", 9, 100);
        bad.status = "error".into();
        bad.status_message = Some("mismatch".into());
        let t = TraceWire {
            trace_id: "t".repeat(32),
            spans: vec![
                span("c", Some("b"), "remote.task.execute", 3, 8_100),
                bad,
                span("a", None, "task.dispatch", 1, 12_400),
                client,
                span("d", Some("c"), "plugin.invoke", 4, 7_900),
            ],
            dropped_spans: 0,
            remote_hints: vec!["spans for work on peer ab12 are held by that node".into()],
        };
        let r = TraceGetResult {
            id: "task-1".into(),
            traces: vec![t],
        };
        let text = render(&r);
        let lines: Vec<&str> = text.lines().collect();
        assert!(
            lines[0].starts_with("Trace tttt") && lines[0].contains("5 spans"),
            "{text}"
        );
        assert_eq!(lines[1], "task.dispatch  12.4ms");
        assert_eq!(
            lines[2],
            "├─ remote.dispatch  11.9ms  client  peer=ab12  transport=iroh"
        );
        assert_eq!(lines[3], "│  └─ remote.task.execute  8.1ms");
        assert_eq!(lines[4], "│     └─ plugin.invoke  7.9ms");
        assert_eq!(lines[5], "└─ integrity.check  100µs  ERROR: mismatch");
        assert_eq!(
            lines[6],
            "note: spans for work on peer ab12 are held by that node"
        );
    }

    /// Event names, status messages and attribute values carry text a
    /// plugin chose: they reach the terminal escaped.
    #[test]
    fn plugin_controlled_text_in_a_trace_cannot_drive_the_terminal() {
        let mut s = span("a", None, "plugin.invoke", 1, 10);
        s.status = "error".into();
        s.status_message = Some("bad\x1b[2K\rforged".into());
        s.attributes = vec![("note".into(), "x\x1b]52;c;aGk=\x07".into())];
        s.events = vec![entangle_rpc::methods::SpanEventWire {
            unix_ms: 0,
            name: "ok\n2026-11-04T15:56:34.719Z WARN  forged\x1b[1A".into(),
            attributes: vec![],
        }];
        let text = render(&TraceGetResult {
            id: "i".into(),
            traces: vec![TraceWire {
                trace_id: "t".repeat(32),
                spans: vec![s],
                dropped_spans: 0,
                remote_hints: vec![],
            }],
        });
        assert!(
            !text.chars().any(|c| c.is_control() && c != '\n'),
            "{text:?}"
        );
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "header, span, event: {text}");
        assert!(
            lines[1].contains("ERROR: bad\\u{1b}[2K\\rforged")
                && lines[1].contains("note=x\\u{1b}]52;c;aGk=\\u{7}"),
            "{text}"
        );
        assert!(
            lines[2].contains("! ok\\n2026-11-04T15:56:34.719Z WARN  forged\\u{1b}[1A"),
            "{text}"
        );
    }

    #[test]
    fn spans_with_missing_parents_become_roots_and_cycles_terminate() {
        let t = TraceWire {
            trace_id: "x".repeat(32),
            spans: vec![
                span("w", Some("remote-parent"), "remote.task.execute", 1, 10),
                span("loop1", Some("loop2"), "a", 2, 1),
                span("loop2", Some("loop1"), "b", 3, 1),
            ],
            dropped_spans: 3,
            remote_hints: vec![],
        };
        let text = render(&TraceGetResult {
            id: "i".into(),
            traces: vec![t],
        });
        assert!(text.contains("remote.task.execute"), "{text}");
        assert!(text.contains("3 more spans"), "{text}");
    }
}
