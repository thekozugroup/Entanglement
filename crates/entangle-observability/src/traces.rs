//! A bounded in-memory store of recent spans behind `entangle trace task`
//! (spec §9.6).
//!
//! [`TraceStore`] is a [`SpanSink`]: finished spans from the daemon's
//! [`SpanLayer`](crate::context::SpanLayer) are filed under their trace id
//! and, when a span carries a `task_id` (or `task`) attribute, indexed by
//! that task id too. It needs no collector: it is fed by the same span
//! pipeline the OTLP exporter uses (see [`FanoutSink`]), so the two can run
//! side by side or the store alone.
//!
//! # Bounds
//!
//! The store holds at most [`TraceConfig::max_spans`] spans in total,
//! [`TraceConfig::max_traces`] traces, and [`MAX_SPANS_PER_TRACE`] per trace
//! (further spans of a full trace are counted, not kept). When a bound is hit
//! a whole trace is evicted, with its task index entries:
//!
//! 1. first the oldest *finished, task-less* trace: its local root span has
//!    closed and none of its spans named a task. Every RPC call the daemon
//!    answers (`logs/read` while following, `status` polled by a script) is
//!    such a trace, a single `rpc.request` span, and it can only be looked up
//!    by trace id;
//! 2. only when there is none, the oldest trace of any kind.
//!
//! So task traces last for the next `max_traces` *tasks*, not the next
//! `max_traces` RPC calls. A trace still in progress (a `plugin.invoke` that
//! closed before the `task.dispatch` carrying the task id) is never treated
//! as task-less.
//!
//! # What is and is not here
//!
//! Only spans this process recorded. For work a peer executed, the store has
//! the submitter's client span (`remote.dispatch`) and, on the peer, a server
//! span that continues the same trace id from the `traceparent` on the wire;
//! each node holds its own half. [`TraceView::remote_hints`] names the peers
//! whose halves are elsewhere.
//!
//! Attribute values are redacted ([`crate::redact`]) before they are stored.

use crate::context::{AttrValue, SpanEvent, SpanKind, SpanRecord, SpanSink};
use crate::redact;
use parking_lot::Mutex;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// Most spans kept for one trace; later ones are counted in
/// [`TraceView::dropped_spans`].
pub const MAX_SPANS_PER_TRACE: usize = 512;
/// Most task ids indexed per trace.
pub const MAX_TASKS_PER_TRACE: usize = 16;

/// Sizing of a [`TraceStore`].
#[derive(Clone, Debug)]
pub struct TraceConfig {
    /// Spans kept in total.
    pub max_spans: usize,
    /// Traces kept at once.
    pub max_traces: usize,
}

impl TraceConfig {
    /// Default span bound.
    pub const DEFAULT_SPANS: usize = 10_000;
    /// Default trace bound.
    pub const DEFAULT_TRACES: usize = 2_000;
    /// Smallest accepted `max_spans`.
    pub const MIN_SPANS: usize = 64;
    /// Largest accepted `max_spans`.
    pub const MAX_SPANS: usize = 1_000_000;
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            max_spans: Self::DEFAULT_SPANS,
            max_traces: Self::DEFAULT_TRACES,
        }
    }
}

/// One trace as the store holds it.
#[derive(Clone, Debug)]
pub struct TraceView {
    /// The 128-bit trace id.
    pub trace_id: [u8; 16],
    /// Its spans, ordered by start time.
    pub spans: Vec<SpanRecord>,
    /// Spans of this trace that were not kept (per-trace bound).
    pub dropped_spans: u64,
}

impl TraceView {
    /// Spans whose parent is not in this store: roots, spans continuing a
    /// trace another node started, and children of spans still open.
    pub fn orphans(&self) -> impl Iterator<Item = &SpanRecord> {
        self.spans.iter().filter(|s| {
            s.parent_span_id
                .is_some_and(|p| !self.spans.iter().any(|o| o.span_id == p))
        })
    }

    /// Peers (from `remote.dispatch` client spans with a `peer` attribute)
    /// that ran work for this trace without any server span here: their
    /// halves of the trace live on those nodes. Plus a marker when a
    /// server-kind span continues a parent this node never recorded.
    pub fn remote_hints(&self) -> Vec<String> {
        let mut hints = Vec::new();
        for s in &self.spans {
            if s.kind == SpanKind::Client {
                let peer = attr_str(s, "peer").unwrap_or("?");
                let answered_here = self
                    .spans
                    .iter()
                    .any(|c| c.parent_span_id == Some(s.span_id) && c.kind == SpanKind::Server);
                if !answered_here {
                    let h = format!("spans for work on peer {peer} are held by that node");
                    if !hints.contains(&h) {
                        hints.push(h);
                    }
                }
            }
        }
        for s in self.orphans() {
            if s.kind == SpanKind::Server {
                let h =
                    "continues a trace started on another node; its earlier spans are held there"
                        .to_owned();
                if !hints.contains(&h) {
                    hints.push(h);
                }
            }
        }
        hints
    }
}

/// The string value of attribute `key` on `s`.
pub fn attr_str<'a>(s: &'a SpanRecord, key: &str) -> Option<&'a str> {
    s.attributes.iter().find_map(|(k, v)| match v {
        AttrValue::Str(v) if k == key => Some(v.as_str()),
        _ => None,
    })
}

struct Entry {
    spans: Vec<SpanRecord>,
    tasks: Vec<String>,
    dropped: u64,
    /// When the trace was first written to: its key in `Inner::order` (and
    /// `Inner::finished_taskless`).
    seq: u64,
    /// Its local root span closed while it indexed no task (see the module
    /// docs): evicted before any other trace.
    finished_taskless: bool,
}

struct Inner {
    cfg: TraceConfig,
    traces: HashMap<[u8; 16], Entry>,
    /// Every held trace, oldest first.
    order: BTreeMap<u64, [u8; 16]>,
    /// The held traces with `finished_taskless` set, oldest first.
    finished_taskless: BTreeMap<u64, [u8; 16]>,
    next_seq: u64,
    by_task: HashMap<String, Vec<[u8; 16]>>,
    total_spans: usize,
    evicted_traces: u64,
}

impl Inner {
    /// The trace to evict next, never `keep` (the one just written to): the
    /// oldest finished task-less trace, else the oldest trace.
    fn victim(&self, keep: &[u8; 16]) -> Option<[u8; 16]> {
        self.finished_taskless
            .values()
            .chain(self.order.values())
            .find(|id| *id != keep)
            .copied()
    }

    fn evict(&mut self, id: &[u8; 16]) {
        let Some(e) = self.traces.remove(id) else {
            return;
        };
        self.order.remove(&e.seq);
        self.finished_taskless.remove(&e.seq);
        self.total_spans -= e.spans.len();
        for t in &e.tasks {
            if let Some(v) = self.by_task.get_mut(t) {
                v.retain(|x| x != id);
                if v.is_empty() {
                    self.by_task.remove(t);
                }
            }
        }
        self.evicted_traces += 1;
    }
}

/// The bounded span store. Cloning shares the same store.
#[derive(Clone)]
pub struct TraceStore {
    inner: Arc<Mutex<Inner>>,
}

impl std::fmt::Debug for TraceStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraceStore").finish_non_exhaustive()
    }
}

impl Default for TraceStore {
    fn default() -> Self {
        Self::new(TraceConfig::default())
    }
}

/// Canonical form of a task id for indexing: lower-case, no dashes.
pub fn normalize_task_id(s: &str) -> String {
    s.chars()
        .filter(|c| *c != '-')
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

impl TraceStore {
    /// A store with `cfg` (sizes clamped).
    pub fn new(mut cfg: TraceConfig) -> Self {
        cfg.max_spans = cfg
            .max_spans
            .clamp(TraceConfig::MIN_SPANS, TraceConfig::MAX_SPANS);
        cfg.max_traces = cfg.max_traces.clamp(1, TraceConfig::MAX_SPANS);
        Self {
            inner: Arc::new(Mutex::new(Inner {
                cfg,
                traces: HashMap::new(),
                order: BTreeMap::new(),
                finished_taskless: BTreeMap::new(),
                next_seq: 0,
                by_task: HashMap::new(),
                total_spans: 0,
                evicted_traces: 0,
            })),
        }
    }

    /// Spans currently held.
    pub fn span_count(&self) -> usize {
        self.inner.lock().total_spans
    }

    /// Traces currently held.
    pub fn trace_count(&self) -> usize {
        self.inner.lock().traces.len()
    }

    /// Traces evicted so far.
    pub fn evicted_traces(&self) -> u64 {
        self.inner.lock().evicted_traces
    }

    /// The trace with this id, if held.
    pub fn by_trace(&self, trace_id: &[u8; 16]) -> Option<TraceView> {
        let g = self.inner.lock();
        g.traces.get(trace_id).map(|e| view(*trace_id, e))
    }

    /// Every held trace that has a span for task `task_id` (any spelling of
    /// the UUID; see [`normalize_task_id`]), the one holding the most spans
    /// first.
    pub fn by_task(&self, task_id: &str) -> Vec<TraceView> {
        let key = normalize_task_id(task_id);
        let g = self.inner.lock();
        let mut out: Vec<TraceView> = g
            .by_task
            .get(&key)
            .into_iter()
            .flatten()
            .filter_map(|t| g.traces.get(t).map(|e| view(*t, e)))
            .collect();
        out.sort_by_key(|v| std::cmp::Reverse(v.spans.len()));
        out
    }
}

fn view(trace_id: [u8; 16], e: &Entry) -> TraceView {
    let mut spans = e.spans.clone();
    spans.sort_by_key(|s| (s.start, s.span_id));
    TraceView {
        trace_id,
        spans,
        dropped_spans: e.dropped,
    }
}

fn redact_attrs(attrs: Vec<(String, AttrValue)>) -> Vec<(String, AttrValue)> {
    attrs
        .into_iter()
        .map(|(k, v)| {
            let v = match v {
                AttrValue::Str(s) => AttrValue::Str(redact::redact_field(&k, &s).into_owned()),
                _ if redact::is_sensitive_name(&k) => AttrValue::Str(redact::REDACTED.to_owned()),
                other => other,
            };
            (k, v)
        })
        .collect()
}

fn redact_span(mut s: SpanRecord) -> SpanRecord {
    s.attributes = redact_attrs(s.attributes);
    s.events = s
        .events
        .into_iter()
        .map(|e| SpanEvent {
            time: e.time,
            name: redact::redact_text(&e.name).into_owned(),
            attributes: redact_attrs(e.attributes),
        })
        .collect();
    if let crate::context::SpanStatus::Error(m) = &s.status {
        s.status = crate::context::SpanStatus::Error(redact::redact_text(m).into_owned());
    }
    s
}

impl SpanSink for TraceStore {
    fn emit(&self, span: SpanRecord) {
        let span = redact_span(span);
        let task = attr_str(&span, "task_id")
            .or_else(|| attr_str(&span, "task"))
            .map(normalize_task_id)
            .filter(|t| !t.is_empty() && t.len() <= 64);
        // No parent at all: the local root of its trace. The registry closes
        // a span only after all its children, so the trace is complete here.
        let is_local_root = span.parent_span_id.is_none();
        let mut g = self.inner.lock();
        let trace_id = span.trace_id;
        if !g.traces.contains_key(&trace_id) {
            let seq = g.next_seq;
            g.next_seq += 1;
            g.traces.insert(
                trace_id,
                Entry {
                    spans: Vec::new(),
                    tasks: Vec::new(),
                    dropped: 0,
                    seq,
                    finished_taskless: false,
                },
            );
            g.order.insert(seq, trace_id);
        }
        let full = g
            .traces
            .get(&trace_id)
            .is_some_and(|e| e.spans.len() >= MAX_SPANS_PER_TRACE);
        if full {
            if let Some(e) = g.traces.get_mut(&trace_id) {
                e.dropped += 1;
            }
        } else {
            if let Some(e) = g.traces.get_mut(&trace_id) {
                e.spans.push(span);
            }
            g.total_spans += 1;
        }
        if let Some(t) = task {
            let tracked = g.traces.get_mut(&trace_id).is_some_and(|e| {
                if e.tasks.contains(&t) {
                    false
                } else if e.tasks.len() < MAX_TASKS_PER_TRACE {
                    e.tasks.push(t.clone());
                    true
                } else {
                    false
                }
            });
            if tracked {
                g.by_task.entry(t).or_default().push(trace_id);
            }
        }
        // Classify: finished and task-less (evicted first), or not (again, if
        // a late span of a finished trace named a task).
        let state = g.traces.get_mut(&trace_id).map(|e| {
            let was = e.finished_taskless;
            if e.tasks.is_empty() {
                e.finished_taskless |= is_local_root;
            } else {
                e.finished_taskless = false;
            }
            (e.seq, was, e.finished_taskless)
        });
        match state {
            Some((seq, false, true)) => {
                g.finished_taskless.insert(seq, trace_id);
            }
            Some((seq, true, false)) => {
                g.finished_taskless.remove(&seq);
            }
            _ => {}
        }
        // Bounds: evict whole traces, never the one just written to unless
        // it is alone.
        while g.total_spans > g.cfg.max_spans || g.traces.len() > g.cfg.max_traces {
            let Some(victim) = g.victim(&trace_id) else {
                break;
            };
            g.evict(&victim);
        }
    }
}

/// A sink that forwards every span to each of its members (the trace store
/// and the OTLP exporter share one [`SpanLayer`](crate::context::SpanLayer)).
pub struct FanoutSink(pub Vec<Arc<dyn SpanSink>>);

impl SpanSink for FanoutSink {
    fn emit(&self, span: SpanRecord) {
        let Some((last, rest)) = self.0.split_last() else {
            return;
        };
        for s in rest {
            s.emit(span.clone());
        }
        last.emit(span);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::SpanStatus;
    use std::time::{Duration, SystemTime};

    fn span(
        trace: u8,
        id: u8,
        parent: Option<u8>,
        name: &str,
        attrs: &[(&str, &str)],
    ) -> SpanRecord {
        let start = SystemTime::UNIX_EPOCH + Duration::from_millis(1000 + u64::from(id));
        SpanRecord {
            trace_id: [trace; 16],
            span_id: [id; 8],
            parent_span_id: parent.map(|p| [p; 8]),
            name: name.to_owned(),
            kind: SpanKind::Internal,
            start,
            end: start + Duration::from_millis(5),
            attributes: attrs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), AttrValue::Str((*v).to_owned())))
                .collect(),
            events: Vec::new(),
            status: SpanStatus::Unset,
        }
    }

    #[test]
    fn indexes_by_task_in_any_uuid_spelling_and_by_trace() {
        let s = TraceStore::default();
        s.emit(span(1, 2, Some(1), "plugin.invoke", &[]));
        s.emit(span(
            1,
            1,
            None,
            "task.dispatch",
            &[("task_id", "6F9619FF-8B86-D011-B42D-00C04FC964FF")],
        ));
        for spelling in [
            "6f9619ff-8b86-d011-b42d-00c04fc964ff",
            "6F9619FF8B86D011B42D00C04FC964FF",
        ] {
            let v = s.by_task(spelling);
            assert_eq!(v.len(), 1, "{spelling}");
            assert_eq!(v[0].spans.len(), 2);
            assert_eq!(v[0].spans[0].name, "task.dispatch", "ordered by start");
        }
        assert!(s.by_trace(&[1; 16]).is_some());
        assert!(s.by_task("00000000-0000-0000-0000-000000000000").is_empty());
    }

    #[test]
    fn span_bound_evicts_whole_oldest_traces_and_their_task_index() {
        let s = TraceStore::new(TraceConfig {
            max_spans: 64,
            max_traces: 1000,
        });
        for t in 1..=40u8 {
            let task = format!("{t:032x}");
            s.emit(span(t, 1, None, "task.dispatch", &[("task_id", &task)]));
            s.emit(span(t, 2, Some(1), "plugin.invoke", &[]));
            s.emit(span(t, 3, Some(1), "plugin.invoke", &[]));
            assert!(
                s.span_count() <= 64,
                "bound broken at trace {t}: {}",
                s.span_count()
            );
        }
        assert!(s.evicted_traces() > 0);
        assert!(
            s.by_task(&format!("{:032x}", 1)).is_empty(),
            "oldest is gone"
        );
        assert!(
            !s.by_task(&format!("{:032x}", 40)).is_empty(),
            "newest kept"
        );
        assert!(s.span_count() <= 64);
    }

    #[test]
    fn trace_bound_and_per_trace_bound_hold() {
        let s = TraceStore::new(TraceConfig {
            max_spans: 100_000,
            max_traces: 5,
        });
        for t in 1..=20u8 {
            s.emit(span(t, 1, None, "x", &[]));
        }
        assert_eq!(s.trace_count(), 5);
        for i in 0..(MAX_SPANS_PER_TRACE as u16 + 50) {
            let mut sp = span(99, 1, None, "y", &[]);
            sp.span_id = [(i % 250) as u8 + 1, (i / 250) as u8, 0, 0, 0, 0, 0, 1];
            s.emit(sp);
        }
        let v = s.by_trace(&[99; 16]).unwrap();
        assert_eq!(v.spans.len(), MAX_SPANS_PER_TRACE);
        assert_eq!(v.dropped_spans, 50);
    }

    /// One finished single-span trace per RPC call, as `methods::dispatch`'s
    /// `rpc.request` root span produces for `logs/read`, `status`, ...
    fn rpc_call(s: &TraceStore, trace: u8) {
        s.emit(span(
            trace,
            1,
            None,
            "rpc.request",
            &[("method", "logs/read")],
        ));
    }

    #[test]
    fn rpc_call_traces_do_not_evict_task_traces() {
        // Trace bound: far more RPC calls than `max_traces`.
        let s = TraceStore::new(TraceConfig {
            max_spans: 100_000,
            max_traces: 5,
        });
        let task = format!("{:032x}", 7);
        s.emit(span(1, 2, Some(1), "plugin.invoke", &[]));
        s.emit(span(1, 1, None, "task.dispatch", &[("task_id", &task)]));
        for t in 10..=250u8 {
            rpc_call(&s, t);
            assert!(s.trace_count() <= 5);
        }
        let v = s.by_task(&task);
        assert_eq!(v.len(), 1, "the task trace survives the RPC calls");
        assert_eq!(v[0].spans.len(), 2);
        assert!(s.evicted_traces() > 0, "RPC-call traces were evicted");
        assert!(s.by_trace(&[250; 16]).is_some(), "the newest call is kept");

        // Span bound: the same.
        let s = TraceStore::new(TraceConfig {
            max_spans: 64,
            max_traces: 100_000,
        });
        s.emit(span(1, 2, Some(1), "plugin.invoke", &[]));
        s.emit(span(1, 1, None, "task.dispatch", &[("task_id", &task)]));
        for t in 10..=250u8 {
            rpc_call(&s, t);
            assert!(s.span_count() <= 64);
        }
        assert_eq!(s.by_task(&task)[0].spans.len(), 2);
    }

    #[test]
    fn an_unfinished_task_trace_outlives_finished_rpc_call_traces() {
        // `plugin.invoke` closes before the `task.dispatch` that carries the
        // task id: the trace has no task index yet while RPC calls go on.
        let s = TraceStore::new(TraceConfig {
            max_spans: 100_000,
            max_traces: 5,
        });
        let task = format!("{:032x}", 8);
        s.emit(span(1, 2, Some(1), "plugin.invoke", &[]));
        for t in 10..=60u8 {
            rpc_call(&s, t);
        }
        s.emit(span(1, 1, None, "task.dispatch", &[("task_id", &task)]));
        let v = s.by_task(&task);
        assert_eq!(v.len(), 1);
        assert_eq!(
            v[0].spans.len(),
            2,
            "plugin.invoke was kept: {:?}",
            v[0].spans
        );
    }

    #[test]
    fn task_traces_are_still_evicted_oldest_first_among_themselves() {
        let s = TraceStore::new(TraceConfig {
            max_spans: 100_000,
            max_traces: 3,
        });
        for t in 1..=6u8 {
            let task = format!("{t:032x}");
            s.emit(span(t, 1, None, "task.dispatch", &[("task_id", &task)]));
            rpc_call(&s, 100 + t);
        }
        assert_eq!(s.trace_count(), 3);
        assert!(s.by_task(&format!("{:032x}", 3)).is_empty());
        assert!(!s.by_task(&format!("{:032x}", 5)).is_empty());
        assert!(!s.by_task(&format!("{:032x}", 6)).is_empty());
    }

    #[test]
    fn secrets_in_attributes_are_redacted() {
        let s = TraceStore::default();
        s.emit(span(
            3,
            1,
            None,
            "rpc.request",
            &[
                ("task_id", "abc"),
                (
                    "capability_token",
                    "En0KEwoEMTIzNBgDIgkKBwgKEgMYgAgSJAgAEiBqS1x3wB9pQ",
                ),
                ("note", "Authorization: Bearer topsecret"),
            ],
        ));
        let v = s.by_trace(&[3; 16]).unwrap();
        let text = format!("{:?}", v.spans[0].attributes);
        assert!(
            !text.contains("En0KEwoE") && !text.contains("topsecret"),
            "{text}"
        );
        assert!(text.contains(redact::REDACTED));
    }

    #[test]
    fn remote_hints_name_peers_and_foreign_parents() {
        let s = TraceStore::default();
        let mut client = span(4, 2, Some(1), "remote.dispatch", &[("peer", "deadbeef")]);
        client.kind = SpanKind::Client;
        s.emit(span(4, 1, None, "task.dispatch", &[("task_id", "t4")]));
        s.emit(client);
        let hints = s.by_trace(&[4; 16]).unwrap().remote_hints();
        assert_eq!(hints.len(), 1);
        assert!(hints[0].contains("deadbeef"), "{hints:?}");

        let mut server = span(5, 7, Some(6), "remote.task.execute", &[]);
        server.kind = SpanKind::Server;
        s.emit(server);
        let hints = s.by_trace(&[5; 16]).unwrap().remote_hints();
        assert!(hints[0].contains("another node"), "{hints:?}");
    }

    #[test]
    fn fanout_delivers_to_every_member() {
        let a = TraceStore::default();
        let b = TraceStore::default();
        let f = FanoutSink(vec![Arc::new(a.clone()), Arc::new(b.clone())]);
        f.emit(span(8, 1, None, "x", &[]));
        assert_eq!(a.span_count(), 1);
        assert_eq!(b.span_count(), 1);
    }
}
