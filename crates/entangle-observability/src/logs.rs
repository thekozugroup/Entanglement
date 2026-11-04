//! Bounded in-memory log ring buffers behind `entangle logs` (spec §9.6).
//!
//! A [`LogLayer`] on the daemon's `tracing` subscriber copies every event
//! from an `entangle*` target into a [`LogHub`]:
//!
//! * one ring per **subsystem** ([`Subsystem`]: `scheduler`, `mesh`,
//!   `gateway`, `daemon`), chosen from the event's target;
//! * one ring per **plugin**, for events carrying a `plugin` field. Output a
//!   plugin printed (a wasm guest's `log` import, its WASI stdout/stderr, a
//!   native plugin's stderr) reaches the hub as events with target
//!   `entangle::plugin` or `entangle::native` and a `plugin` field, so it
//!   lands in that plugin's ring only. Any other event that names a plugin
//!   (`ENTANGLE-` warnings from the kernel, scheduler events about a task) is
//!   filed under the plugin *and* its subsystem.
//!
//! # Bounds
//!
//! Every ring holds at most [`LogConfig::lines_per_source`] lines (the oldest
//! is dropped first). At most [`LogConfig::max_plugin_sources`] plugin rings
//! exist (the one written to longest ago is evicted), plugin keys are
//! length-limited, and each line is clipped ([`MAX_MESSAGE_BYTES`],
//! [`MAX_FIELDS`], [`MAX_FIELD_BYTES`]); a plugin that floods its ring evicts
//! only its own lines. Reads are bounded too ([`LogQuery::limit`],
//! [`MAX_PAGE_BYTES`]).
//!
//! # Secrets
//!
//! Message and field values pass through [`crate::redact`] before they are
//! stored; the buffer never holds the original.
//!
//! # Reading
//!
//! Lines carry a hub-wide, strictly increasing sequence number. A reader
//! keeps the `next_cursor` of its last page and asks for lines `after` it;
//! [`LogHub::subscribe`] wakes it when something new arrives (the daemon's
//! long-poll `logs/read` is built on that).

use crate::error::QueryError;
use crate::redact;
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// Longest message kept per line, in bytes.
pub const MAX_MESSAGE_BYTES: usize = 4096;
/// Most fields kept per line.
pub const MAX_FIELDS: usize = 24;
/// Longest field value kept, in bytes.
pub const MAX_FIELD_BYTES: usize = 512;
/// Longest plugin id accepted as a ring key, in bytes.
pub const MAX_PLUGIN_KEY_BYTES: usize = 200;
/// Soft bound on the bytes of one [`LogPage`].
pub const MAX_PAGE_BYTES: usize = 256 * 1024;
/// Most lines one read returns, whatever the caller asks.
pub const MAX_PAGE_LINES: usize = 1000;

/// `tracing` target for output a wasm plugin printed.
pub const PLUGIN_OUTPUT_TARGET: &str = "entangle::plugin";
/// `tracing` target for output a native plugin printed on stderr.
pub const NATIVE_OUTPUT_TARGET: &str = "entangle::native";

/// Event severity, ordered `Trace < Debug < Info < Warn < Error`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogLevel {
    /// `TRACE`.
    Trace,
    /// `DEBUG`.
    Debug,
    /// `INFO`.
    Info,
    /// `WARN`.
    Warn,
    /// `ERROR`.
    Error,
}

impl LogLevel {
    /// Lower-case name (`info`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }

    /// Parse a case-insensitive level name (`warning` is accepted for `warn`).
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "trace" => Self::Trace,
            "debug" => Self::Debug,
            "info" => Self::Info,
            "warn" | "warning" => Self::Warn,
            "error" => Self::Error,
            _ => return None,
        })
    }

    fn from_tracing(l: &Level) -> Self {
        match *l {
            Level::TRACE => Self::Trace,
            Level::DEBUG => Self::Debug,
            Level::INFO => Self::Info,
            Level::WARN => Self::Warn,
            Level::ERROR => Self::Error,
        }
    }

    /// The matching `tracing` level.
    pub const fn to_tracing(self) -> Level {
        match self {
            Self::Trace => Level::TRACE,
            Self::Debug => Level::DEBUG,
            Self::Info => Level::INFO,
            Self::Warn => Level::WARN,
            Self::Error => Level::ERROR,
        }
    }
}

/// A daemon subsystem with its own ring.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Subsystem {
    /// Scheduler, dispatcher, remote execution, streams.
    Scheduler,
    /// Mesh transports, discovery, pairing, peers.
    Mesh,
    /// The MCP gateway and agent host.
    Gateway,
    /// Everything else: kernel, host, broker, RPC, maintenance.
    Daemon,
}

impl Subsystem {
    /// Every subsystem.
    pub const ALL: [Subsystem; 4] = [Self::Scheduler, Self::Mesh, Self::Gateway, Self::Daemon];

    /// The name operators type (`scheduler`).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Scheduler => "scheduler",
            Self::Mesh => "mesh",
            Self::Gateway => "gateway",
            Self::Daemon => "daemon",
        }
    }

    /// Parse a subsystem name.
    pub fn from_name(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|x| x.name() == s)
    }

    const fn index(self) -> usize {
        match self {
            Self::Scheduler => 0,
            Self::Mesh => 1,
            Self::Gateway => 2,
            Self::Daemon => 3,
        }
    }

    /// The subsystem an event from `target` belongs to.
    pub fn of_target(target: &str) -> Self {
        let t = target.to_ascii_lowercase();
        if t.contains("scheduler") || t.starts_with("entangle_bin::remote") {
            Self::Scheduler
        } else if t.contains("mesh")
            || t.contains("tailscale")
            || t.contains("pairing")
            || t.contains("entangle_peers")
            || t.starts_with("entangle_bin::diag")
        {
            Self::Mesh
        } else if t.contains("agent_host") || t.contains("gateway") {
            Self::Gateway
        } else {
            Self::Daemon
        }
    }
}

/// One stored event.
#[derive(Clone, Debug, PartialEq)]
pub struct LogLine {
    /// Hub-wide sequence number (strictly increasing, starts at 1).
    pub seq: u64,
    /// Wall-clock time, milliseconds since the Unix epoch.
    pub unix_ms: u64,
    /// Severity.
    pub level: LogLevel,
    /// The event's `tracing` target.
    pub target: String,
    /// The event's name: its `event` field (`StalledEvent`), or an explicit
    /// `name:` given to the macro.
    pub event: Option<String>,
    /// The message (redacted, clipped).
    pub message: String,
    /// The other fields in recording order (redacted, clipped). The
    /// `plugin` field is omitted: the ring already says which plugin.
    pub fields: Vec<(String, String)>,
}

impl LogLine {
    fn approx_bytes(&self) -> usize {
        64 + self.target.len()
            + self.event.as_ref().map_or(0, String::len)
            + self.message.len()
            + self
                .fields
                .iter()
                .map(|(k, v)| k.len() + v.len() + 8)
                .sum::<usize>()
    }

    /// Whether this line passes `filter`: the event name equals it
    /// (case-insensitively), or the message, the target or a field value
    /// contains it (case-insensitively).
    pub fn matches_filter(&self, filter: &str) -> bool {
        let f = filter.to_ascii_lowercase();
        if self
            .event
            .as_deref()
            .is_some_and(|e| e.eq_ignore_ascii_case(filter))
        {
            return true;
        }
        self.message.to_ascii_lowercase().contains(&f)
            || self.target.to_ascii_lowercase().contains(&f)
            || self
                .fields
                .iter()
                .any(|(_, v)| v.to_ascii_lowercase().contains(&f))
    }
}

/// Which ring a read targets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogSource {
    /// A subsystem ring.
    Subsystem(Subsystem),
    /// A plugin ring, keyed by the full plugin id.
    Plugin(String),
}

/// Sizing of a [`LogHub`].
#[derive(Clone, Debug)]
pub struct LogConfig {
    /// Lines kept per ring.
    pub lines_per_source: usize,
    /// Plugin rings kept at once.
    pub max_plugin_sources: usize,
    /// Events below this level are not stored.
    pub capture_level: LogLevel,
}

impl LogConfig {
    /// Default ring size.
    pub const DEFAULT_LINES: usize = 1000;
    /// Default number of plugin rings.
    pub const DEFAULT_PLUGINS: usize = 128;
    /// Smallest accepted `lines_per_source`.
    pub const MIN_LINES: usize = 16;
    /// Largest accepted `lines_per_source`.
    pub const MAX_LINES: usize = 100_000;
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            lines_per_source: Self::DEFAULT_LINES,
            max_plugin_sources: Self::DEFAULT_PLUGINS,
            capture_level: LogLevel::Info,
        }
    }
}

/// A read request.
#[derive(Clone, Debug)]
pub struct LogQuery {
    /// Which ring.
    pub source: LogSource,
    /// `None`: the newest matching lines (tail). `Some(c)`: matching lines
    /// with a sequence number greater than `c`, oldest first.
    pub after: Option<u64>,
    /// Lines below this level are skipped.
    pub min_level: LogLevel,
    /// See [`LogLine::matches_filter`].
    pub filter: Option<String>,
    /// Lines older than this (Unix milliseconds) are skipped.
    pub since_unix_ms: Option<u64>,
    /// At most this many lines (clamped to `1..=`[`MAX_PAGE_LINES`]).
    pub limit: usize,
}

impl LogQuery {
    /// A tail read of `source` with no filters.
    pub fn tail(source: LogSource, limit: usize) -> Self {
        Self {
            source,
            after: None,
            min_level: LogLevel::Trace,
            filter: None,
            since_unix_ms: None,
            limit,
        }
    }

    fn matches(&self, l: &LogLine) -> bool {
        l.level >= self.min_level
            && self.since_unix_ms.is_none_or(|s| l.unix_ms >= s)
            && self.filter.as_deref().is_none_or(|f| l.matches_filter(f))
    }
}

/// The answer to a [`LogQuery`].
#[derive(Clone, Debug, PartialEq)]
pub struct LogPage {
    /// Matching lines, oldest first.
    pub lines: Vec<LogLine>,
    /// Pass this as `after` next time.
    pub next_cursor: u64,
    /// More matching lines were available than fit in this page.
    pub more: bool,
    /// Lines between the caller's cursor and the oldest line still held were
    /// evicted before they could be read.
    pub truncated: bool,
}

#[derive(Default)]
struct Ring {
    lines: VecDeque<LogLine>,
    /// Highest sequence number evicted from this ring.
    evicted_up_to: u64,
    /// Hub tick of the last write (plugin ring eviction order).
    last_write: u64,
}

struct Inner {
    cfg: LogConfig,
    subsystems: [Ring; 4],
    plugins: HashMap<String, Ring>,
    next_seq: u64,
    tick: u64,
}

/// The shared store. Cloning shares the same buffers.
#[derive(Clone)]
pub struct LogHub {
    inner: Arc<Mutex<Inner>>,
    notify: Arc<watch::Sender<u64>>,
}

impl std::fmt::Debug for LogHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogHub").finish_non_exhaustive()
    }
}

impl Default for LogHub {
    fn default() -> Self {
        Self::new(LogConfig::default())
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl LogHub {
    /// A hub with `cfg` (sizes are clamped to sane bounds).
    pub fn new(mut cfg: LogConfig) -> Self {
        cfg.lines_per_source = cfg
            .lines_per_source
            .clamp(LogConfig::MIN_LINES, LogConfig::MAX_LINES);
        cfg.max_plugin_sources = cfg.max_plugin_sources.clamp(1, 4096);
        let (tx, _) = watch::channel(0);
        Self {
            inner: Arc::new(Mutex::new(Inner {
                cfg,
                subsystems: Default::default(),
                plugins: HashMap::new(),
                next_seq: 1,
                tick: 0,
            })),
            notify: Arc::new(tx),
        }
    }

    /// The configured capture level.
    pub fn capture_level(&self) -> LogLevel {
        self.inner.lock().cfg.capture_level
    }

    /// The per-ring line bound.
    pub fn lines_per_source(&self) -> usize {
        self.inner.lock().cfg.lines_per_source
    }

    /// A receiver whose value is the newest sequence number; it changes on
    /// every stored line.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.notify.subscribe()
    }

    /// The newest sequence number handed out (0 before the first line).
    pub fn latest_seq(&self) -> u64 {
        self.inner.lock().next_seq - 1
    }

    /// Ids of the plugins that have a ring, sorted.
    pub fn plugin_ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self.inner.lock().plugins.keys().cloned().collect();
        v.sort();
        v
    }

    /// Lines currently held by `source`.
    pub fn len(&self, source: &LogSource) -> usize {
        let g = self.inner.lock();
        match source {
            LogSource::Subsystem(s) => g.subsystems[s.index()].lines.len(),
            LogSource::Plugin(p) => g.plugins.get(p).map_or(0, |r| r.lines.len()),
        }
    }

    /// Whether `source` holds no lines.
    pub fn is_empty(&self, source: &LogSource) -> bool {
        self.len(source) == 0
    }

    /// Store one event. `plugin` files it under that plugin's ring;
    /// `subsystem` (when `Some`) under that subsystem's. `line.seq` is
    /// assigned here.
    pub fn push(&self, plugin: Option<&str>, subsystem: Option<Subsystem>, mut line: LogLine) {
        let seq = {
            let mut g = self.inner.lock();
            let seq = g.next_seq;
            g.next_seq += 1;
            g.tick += 1;
            let tick = g.tick;
            line.seq = seq;
            let cap = g.cfg.lines_per_source;
            if let Some(s) = subsystem {
                let ring = &mut g.subsystems[s.index()];
                ring.last_write = tick;
                push_ring(ring, line.clone(), cap);
            }
            if let Some(p) = plugin {
                if !g.plugins.contains_key(p) && g.plugins.len() >= g.cfg.max_plugin_sources {
                    let oldest = g
                        .plugins
                        .iter()
                        .min_by_key(|(_, r)| r.last_write)
                        .map(|(k, _)| k.clone());
                    if let Some(k) = oldest {
                        g.plugins.remove(&k);
                    }
                }
                let ring = g.plugins.entry(p.to_owned()).or_default();
                ring.last_write = tick;
                push_ring(ring, line, cap);
            }
            seq
        };
        self.notify.send_replace(seq);
    }

    /// Answer `q`. A plugin with no ring yet reads as empty.
    pub fn read(&self, q: &LogQuery) -> LogPage {
        let limit = q.limit.clamp(1, MAX_PAGE_LINES);
        let g = self.inner.lock();
        let latest = g.next_seq - 1;
        let empty = Ring::default();
        let ring = match &q.source {
            LogSource::Subsystem(s) => &g.subsystems[s.index()],
            LogSource::Plugin(p) => g.plugins.get(p).unwrap_or(&empty),
        };
        match q.after {
            None => {
                // Tail: scan from the newest end.
                let mut picked: Vec<LogLine> = Vec::new();
                let mut bytes = 0usize;
                let mut more = false;
                for l in ring.lines.iter().rev().filter(|l| q.matches(l)) {
                    if picked.len() == limit || bytes + l.approx_bytes() > MAX_PAGE_BYTES {
                        more = true;
                        break;
                    }
                    bytes += l.approx_bytes();
                    picked.push(l.clone());
                }
                picked.reverse();
                LogPage {
                    lines: picked,
                    next_cursor: latest,
                    more,
                    truncated: false,
                }
            }
            Some(after) => {
                let truncated = ring.evicted_up_to > after;
                let mut picked: Vec<LogLine> = Vec::new();
                let mut bytes = 0usize;
                let mut more = false;
                for l in ring.lines.iter().filter(|l| l.seq > after && q.matches(l)) {
                    if picked.len() == limit || bytes + l.approx_bytes() > MAX_PAGE_BYTES {
                        more = true;
                        break;
                    }
                    bytes += l.approx_bytes();
                    picked.push(l.clone());
                }
                // When the page is full the cursor stops at its last line;
                // otherwise everything up to `latest` has been looked at.
                let next_cursor = if more {
                    picked.last().map_or(after, |l| l.seq)
                } else {
                    latest.max(after)
                };
                LogPage {
                    lines: picked,
                    next_cursor,
                    more,
                    truncated,
                }
            }
        }
    }
}

fn push_ring(ring: &mut Ring, line: LogLine, cap: usize) {
    if ring.lines.len() >= cap {
        if let Some(old) = ring.lines.pop_front() {
            ring.evicted_up_to = ring.evicted_up_to.max(old.seq);
        }
    }
    ring.lines.push_back(line);
}

/// Resolve what an operator typed to a log source: a subsystem name, a full
/// plugin id, or a plugin name (`hello-world`, or `hello-world@0.1.0`) that
/// matches exactly one of `known_plugins`.
pub fn resolve_source(
    name: &str,
    known_plugins: impl IntoIterator<Item = String>,
) -> Result<LogSource, QueryError> {
    if let Some(s) = Subsystem::from_name(name) {
        return Ok(LogSource::Subsystem(s));
    }
    let mut known: Vec<String> = known_plugins.into_iter().collect();
    known.sort();
    known.dedup();
    if known.iter().any(|k| k == name) {
        return Ok(LogSource::Plugin(name.to_owned()));
    }
    let matches: Vec<&String> = known
        .iter()
        .filter(|k| {
            let rest = k.split_once('/').map_or(k.as_str(), |(_, r)| r);
            rest == name || rest.split('@').next() == Some(name)
        })
        .collect();
    match matches.as_slice() {
        [one] => Ok(LogSource::Plugin((*one).clone())),
        [] => Err(QueryError::UnknownLogSource {
            name: name.to_owned(),
            subsystems: Subsystem::ALL.map(Subsystem::name).join(", "),
            plugins: if known.is_empty() {
                "none".to_owned()
            } else {
                known.join(", ")
            },
        }),
        many => Err(QueryError::AmbiguousPlugin {
            name: name.to_owned(),
            matches: many
                .iter()
                .map(|m| m.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        }),
    }
}

// ── the tracing layer ────────────────────────────────────────────────────────

/// Whether the layer should see an event or span with this metadata:
/// `entangle*` targets at or above `level`. Use it as the per-layer filter so
/// a quiet console (`RUST_LOG`) does not starve the buffers.
pub fn is_captured(meta: &tracing::Metadata<'_>, level: LogLevel) -> bool {
    meta.target().starts_with("entangle") && LogLevel::from_tracing(meta.level()) >= level
}

/// A `tracing` layer filling a [`LogHub`].
#[derive(Clone)]
pub struct LogLayer {
    hub: LogHub,
}

impl LogLayer {
    /// A layer writing to `hub`.
    pub fn new(hub: LogHub) -> Self {
        Self { hub }
    }
}

#[derive(Default)]
struct EventVisitor {
    message: Option<String>,
    event: Option<String>,
    plugin: Option<String>,
    fields: Vec<(String, String)>,
}

impl EventVisitor {
    fn put(&mut self, field: &Field, value: String) {
        match field.name() {
            "message" => self.message = Some(value),
            "event" => self.event = Some(value),
            "plugin" => self.plugin = Some(value),
            // `log` crate bridge metadata.
            n if n.starts_with("log.") => {}
            n => {
                if self.fields.len() < MAX_FIELDS {
                    self.fields.push((n.to_owned(), value));
                }
            }
        }
    }
}

impl Visit for EventVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field, value.to_owned());
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let mut s = String::new();
        let _ = write!(s, "{value:?}");
        self.put(field, s);
    }
}

fn clip(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut cut = max;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        s.push('…');
    }
    s
}

/// A plugin id is `<publisher>/<name>@<version>`: printable, no control
/// characters, bounded. Anything else is not used as a ring key (an event's
/// `plugin` field is attacker-influenced for remote work).
fn valid_plugin_key(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_PLUGIN_KEY_BYTES
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '@' | '.' | '-' | '_' | '+'))
}

impl<S: Subscriber> Layer<S> for LogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let level = LogLevel::from_tracing(meta.level());
        if level < self.hub.capture_level() || !meta.target().starts_with("entangle") {
            return;
        }
        let mut v = EventVisitor::default();
        event.record(&mut v);
        let name = meta.name();
        let event_name = v
            .event
            .take()
            .or_else(|| (!name.starts_with("event ")).then(|| name.to_owned()))
            .map(|e| clip(redact::redact_text(&e).into_owned(), 128));
        let line = LogLine {
            seq: 0,
            unix_ms: now_ms(),
            level,
            target: meta.target().to_owned(),
            event: event_name,
            message: clip(
                redact::redact_text(v.message.as_deref().unwrap_or_default()).into_owned(),
                MAX_MESSAGE_BYTES,
            ),
            fields: v
                .fields
                .into_iter()
                .map(|(k, val)| {
                    let val = clip(redact::redact_field(&k, &val).into_owned(), MAX_FIELD_BYTES);
                    (k, val)
                })
                .collect(),
        };
        let plugin = v.plugin.filter(|p| valid_plugin_key(p));
        let output_target = matches!(meta.target(), PLUGIN_OUTPUT_TARGET | NATIVE_OUTPUT_TARGET);
        let subsystem = if output_target && plugin.is_some() {
            None
        } else {
            Some(Subsystem::of_target(meta.target()))
        };
        self.hub.push(plugin.as_deref(), subsystem, line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::prelude::*;

    fn hub(lines: usize) -> LogHub {
        LogHub::new(LogConfig {
            lines_per_source: lines,
            max_plugin_sources: 3,
            capture_level: LogLevel::Debug,
        })
    }

    fn with_layer<R>(h: &LogHub, f: impl FnOnce() -> R) -> R {
        let sub = tracing_subscriber::registry().with(LogLayer::new(h.clone()));
        tracing::subscriber::with_default(sub, f)
    }

    fn line(msg: &str) -> LogLine {
        LogLine {
            seq: 0,
            unix_ms: 1,
            level: LogLevel::Info,
            target: "entangle_bin".into(),
            event: None,
            message: msg.into(),
            fields: vec![],
        }
    }

    #[test]
    fn ring_bound_holds_and_oldest_goes_first() {
        let h = hub(16);
        for i in 0..100 {
            h.push(None, Some(Subsystem::Daemon), line(&format!("m{i}")));
        }
        let src = LogSource::Subsystem(Subsystem::Daemon);
        assert_eq!(h.len(&src), 16);
        let page = h.read(&LogQuery::tail(src, 1000));
        assert_eq!(page.lines.len(), 16);
        assert_eq!(page.lines[0].message, "m84");
        assert_eq!(page.lines[15].message, "m99");
        assert_eq!(page.next_cursor, 100);
    }

    #[test]
    fn plugin_rings_are_bounded_in_number() {
        let h = hub(16);
        for p in ["a/p1@1", "a/p2@1", "a/p3@1", "a/p4@1"] {
            h.push(Some(p), None, line("x"));
        }
        let ids = h.plugin_ids();
        assert_eq!(ids.len(), 3, "{ids:?}");
        assert!(
            !ids.contains(&"a/p1@1".to_owned()),
            "oldest evicted: {ids:?}"
        );
    }

    #[test]
    fn follow_reads_only_newer_lines_and_reports_truncation() {
        let h = hub(16);
        let src = LogSource::Subsystem(Subsystem::Mesh);
        for i in 0..5 {
            h.push(None, Some(Subsystem::Mesh), line(&format!("m{i}")));
        }
        let mut q = LogQuery::tail(src, 100);
        q.after = Some(3);
        let page = h.read(&q);
        assert_eq!(
            page.lines
                .iter()
                .map(|l| l.message.as_str())
                .collect::<Vec<_>>(),
            ["m3", "m4"]
        );
        assert!(!page.truncated);
        for i in 5..60 {
            h.push(None, Some(Subsystem::Mesh), line(&format!("m{i}")));
        }
        q.after = Some(5);
        assert!(h.read(&q).truncated, "lines 6.. were evicted");
    }

    #[test]
    fn page_limit_moves_the_cursor_only_to_the_last_returned_line() {
        let h = hub(100);
        for i in 0..10 {
            h.push(None, Some(Subsystem::Daemon), line(&format!("m{i}")));
        }
        let mut q = LogQuery::tail(LogSource::Subsystem(Subsystem::Daemon), 4);
        q.after = Some(0);
        let p1 = h.read(&q);
        assert_eq!(p1.lines.len(), 4);
        assert!(p1.more);
        assert_eq!(p1.next_cursor, 4);
        q.after = Some(p1.next_cursor);
        let p2 = h.read(&q);
        assert_eq!(p2.lines[0].message, "m4");
    }

    #[test]
    fn layer_routes_by_target_and_plugin_field_and_keeps_output_off_subsystems() {
        let h = hub(100);
        with_layer(&h, || {
            tracing::info!(target: "entangle_scheduler::dispatcher", "scheduled");
            tracing::warn!(target: "entangle::scheduler::stream", event = "StalledEvent", task = "t1", "stalled");
            tracing::info!(target: "entangle_mesh_iroh", "connected");
            tracing::info!(target: "entangle_agent_host::gateway", "session");
            tracing::info!(target: "entangle_runtime::kernel", "loaded");
            tracing::info!(target: "entangle::plugin", plugin = "aa/one@1", stream = "stdout", "hello from one");
            tracing::info!(target: "entangle::plugin", plugin = "aa/two@1", stream = "stdout", "hello from two");
            tracing::warn!(target: "entangle_runtime::kernel", plugin = "aa/one@1", "capability denied");
            tracing::info!(target: "hyper::proto", "not ours");
        });
        let msgs = |s: LogSource| -> Vec<String> {
            h.read(&LogQuery::tail(s, 100))
                .lines
                .into_iter()
                .map(|l| l.message)
                .collect()
        };
        assert_eq!(
            msgs(LogSource::Subsystem(Subsystem::Scheduler)),
            ["scheduled", "stalled"]
        );
        assert_eq!(msgs(LogSource::Subsystem(Subsystem::Mesh)), ["connected"]);
        assert_eq!(msgs(LogSource::Subsystem(Subsystem::Gateway)), ["session"]);
        assert_eq!(
            msgs(LogSource::Subsystem(Subsystem::Daemon)),
            ["loaded", "capability denied"]
        );
        assert_eq!(
            msgs(LogSource::Plugin("aa/one@1".into())),
            ["hello from one", "capability denied"]
        );
        assert_eq!(
            msgs(LogSource::Plugin("aa/two@1".into())),
            ["hello from two"]
        );
    }

    #[test]
    fn level_and_filter_and_event_name() {
        let h = hub(100);
        with_layer(&h, || {
            tracing::debug!(target: "entangle::scheduler::stream", "chatter");
            tracing::info!(target: "entangle::scheduler::stream", "routine");
            tracing::warn!(target: "entangle::scheduler::stream", event = "StalledEvent", peer_id = "abc", "stream stalled");
            tracing::error!(target: "entangle::scheduler::stream", "boom");
        });
        let src = LogSource::Subsystem(Subsystem::Scheduler);
        let mut q = LogQuery::tail(src.clone(), 100);
        q.min_level = LogLevel::Warn;
        assert_eq!(h.read(&q).lines.len(), 2);
        let mut q = LogQuery::tail(src.clone(), 100);
        q.filter = Some("StalledEvent".into());
        let page = h.read(&q);
        assert_eq!(page.lines.len(), 1);
        assert_eq!(page.lines[0].event.as_deref(), Some("StalledEvent"));
        assert_eq!(
            page.lines[0].fields,
            [("peer_id".to_owned(), "abc".to_owned())]
        );
        let mut q = LogQuery::tail(src, 100);
        q.filter = Some("ROUTINE".into());
        assert_eq!(h.read(&q).lines.len(), 1, "substring, case-insensitive");
    }

    #[test]
    fn secrets_never_reach_the_buffer() {
        let h = hub(100);
        with_layer(&h, || {
            tracing::info!(
                target: "entangle_bin",
                capability_token = "En0KEwoEMTIzNBgDIgkKBwgKEgMYgAgSJAgAEiBqS1x3wB9pQ",
                passphrase = "correcthorse",
                note = "Bearer sekrit.value rest",
                "login with password=hunter2"
            );
        });
        let page = h.read(&LogQuery::tail(LogSource::Subsystem(Subsystem::Daemon), 10));
        let l = &page.lines[0];
        let all = format!("{l:?}");
        for leak in ["En0KEwoE", "correcthorse", "sekrit", "hunter2"] {
            assert!(!all.contains(leak), "{leak} leaked: {all}");
        }
        assert!(all.contains(redact::REDACTED));
    }

    #[test]
    fn oversized_fields_are_clipped_and_bad_plugin_keys_ignored() {
        let h = hub(100);
        let big = "x".repeat(10_000);
        with_layer(&h, || {
            tracing::info!(target: "entangle_bin", blob = %big, "m");
            tracing::info!(target: "entangle::plugin", plugin = "not a valid\nkey", "bad key");
        });
        assert!(h.plugin_ids().is_empty());
        let page = h.read(&LogQuery::tail(LogSource::Subsystem(Subsystem::Daemon), 10));
        assert!(page.lines[0].fields[0].1.len() <= MAX_FIELD_BYTES + 4);
        assert_eq!(
            page.lines.len(),
            2,
            "bad-key line still lands in a subsystem"
        );
    }

    #[test]
    fn source_resolution() {
        let known = || {
            [
                "aa/hello@0.1.0".to_owned(),
                "bb/hello@0.2.0".to_owned(),
                "aa/solo@1.0.0".to_owned(),
            ]
        };
        assert_eq!(
            resolve_source("scheduler", known()).unwrap(),
            LogSource::Subsystem(Subsystem::Scheduler)
        );
        assert_eq!(
            resolve_source("solo", known()).unwrap(),
            LogSource::Plugin("aa/solo@1.0.0".into())
        );
        assert_eq!(
            resolve_source("solo@1.0.0", known()).unwrap(),
            LogSource::Plugin("aa/solo@1.0.0".into())
        );
        assert_eq!(
            resolve_source("bb/hello@0.2.0", known()).unwrap(),
            LogSource::Plugin("bb/hello@0.2.0".into())
        );
        let e = resolve_source("hello", known()).unwrap_err().to_string();
        assert!(
            e.starts_with("ENTANGLE-E0681") && e.contains("aa/hello@0.1.0"),
            "{e}"
        );
        let e = resolve_source("nope", known()).unwrap_err().to_string();
        assert!(
            e.starts_with("ENTANGLE-E0680") && e.contains("scheduler, mesh, gateway, daemon"),
            "{e}"
        );
    }

    #[tokio::test]
    async fn subscribers_are_woken_by_new_lines() {
        let h = hub(16);
        let mut rx = h.subscribe();
        let h2 = h.clone();
        let t = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            h2.push(None, Some(Subsystem::Daemon), line("late"));
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), rx.changed())
            .await
            .expect("woken")
            .expect("open");
        assert_eq!(*rx.borrow(), 1);
        t.await.unwrap();
    }
}
