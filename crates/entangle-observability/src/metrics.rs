//! Prometheus metrics registry and text exposition (spec §9.6).
//!
//! A small, dependency-free registry that emits valid Prometheus text-format
//! 0.0.4 `# HELP` / `# TYPE` / sample lines from counters, gauges and
//! histograms. The daemon owns one [`Registry`], hands clones to the
//! subsystems that record into it (clones share state) and serves
//! [`Registry::render`] on its scrape endpoint and over RPC.
//!
//! # Cardinality
//!
//! Every metric family holds at most [`MAX_SERIES_PER_FAMILY`] label sets.
//! A sample for a *new* label set beyond that is dropped and counted in
//! `entangle_metrics_dropped_series_total`, so a bug (or hostile input) that
//! leaks an unbounded value into a label degrades to a visible counter
//! instead of unbounded memory growth. Callers still pick bounded label
//! values; this is the backstop.
//!
//! # Collectors
//!
//! State that is cheaper to *read at scrape time* than to push on every
//! change (loaded plugins, peer counts, ...) is exposed through
//! [`Registry::register_collector`]: each collector runs just before
//! [`Registry::render`] and sets its gauges.

use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Maximum number of distinct label sets kept per metric family.
pub const MAX_SERIES_PER_FAMILY: usize = 512;

/// Name of the self-metric counting samples dropped by the series cap.
pub const DROPPED_SERIES_METRIC: &str = "entangle_metrics_dropped_series_total";

type Collector = Arc<dyn Fn(&Registry) + Send + Sync>;

/// Internal record kept for each metric family.
#[derive(Clone, Debug)]
struct Family {
    help: String,
    kind: Kind,
    samples: Vec<Sample>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Counter,
    Gauge,
    Histogram,
}

impl Kind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Histogram => "histogram",
        }
    }
}

#[derive(Clone, Debug)]
struct Sample {
    labels: BTreeMap<String, String>,
    value: f64,
    /// Histogram-only: ordered bucket upper bounds and cumulative counts.
    ///
    /// For non-histogram samples this is empty.
    histogram: Vec<(f64, u64)>,
    /// Histogram-only: cumulative `+Inf` bucket count and running sum.
    hist_count: u64,
    hist_sum: f64,
}

/// Prometheus registry. Cloning is cheap and clones share all state.
#[derive(Clone, Default)]
pub struct Registry {
    families: Arc<Mutex<BTreeMap<String, Family>>>,
    collectors: Arc<Mutex<Vec<Collector>>>,
    dropped_series: Arc<AtomicU64>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("families", &self.families.lock().len())
            .field("collectors", &self.collectors.lock().len())
            .finish()
    }
}

impl Registry {
    /// Construct an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment (or initialise) a counter sample by `delta`.
    ///
    /// `name` is the metric family name (e.g. `entangle_kernel_invocations_total`).
    /// `labels` may be empty.
    pub fn inc_counter(&self, name: &str, help: &str, labels: &[(&str, &str)], delta: f64) {
        self.upsert(name, help, Kind::Counter, labels, |v| *v += delta);
    }

    /// Set (or initialise) a gauge sample to `value`.
    pub fn set_gauge(&self, name: &str, help: &str, labels: &[(&str, &str)], value: f64) {
        self.upsert(name, help, Kind::Gauge, labels, |v| *v = value);
    }

    /// Set a counter sample to an absolute `value`.
    ///
    /// For counters whose authoritative total is kept elsewhere (a collector
    /// mirroring an atomic). The value must never decrease between scrapes.
    pub fn set_counter(&self, name: &str, help: &str, labels: &[(&str, &str)], value: f64) {
        self.upsert(name, help, Kind::Counter, labels, |v| *v = value);
    }

    /// Remove every sample of `name`, keeping nothing of the family.
    ///
    /// Collectors that mirror a changing set (loaded plugins) call this
    /// before re-setting their gauges so series for vanished members do not
    /// linger.
    pub fn clear_family(&self, name: &str) {
        self.families.lock().remove(name);
    }

    /// Run `collector` just before every [`Registry::render`].
    ///
    /// The collector sets gauges (or absolute counters) from live state. It
    /// must be quick and must not call [`Registry::render`].
    pub fn register_collector(&self, collector: impl Fn(&Registry) + Send + Sync + 'static) {
        self.collectors.lock().push(Arc::new(collector));
    }

    /// The current value of a counter or gauge sample, for tests and
    /// diagnostics. `None` when the family or label set does not exist.
    pub fn value(&self, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
        let want: BTreeMap<String, String> = labels
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let guard = self.families.lock();
        let family = guard.get(name)?;
        family.samples.iter().find(|s| s.labels == want).map(|s| {
            if family.kind == Kind::Histogram {
                s.hist_count as f64
            } else {
                s.value
            }
        })
    }

    /// Number of samples dropped by the per-family series cap so far.
    pub fn dropped_series(&self) -> u64 {
        self.dropped_series.load(Ordering::Relaxed)
    }

    /// Observe a sample for a histogram metric.
    ///
    /// `buckets` is the ordered list of upper-inclusive bucket boundaries
    /// (the implicit `+Inf` bucket is always present). The sample is added
    /// to every bucket whose boundary is >= `value`.
    ///
    /// If the family does not yet exist, it is created with the supplied
    /// bucket layout; later `observe_histogram` calls on the same family
    /// MUST pass the same `buckets` slice — mismatches are tolerated for
    /// existing samples but a freshly-seen `labels` set will inherit the
    /// first-seen buckets.
    pub fn observe_histogram(
        &self,
        name: &str,
        help: &str,
        labels: &[(&str, &str)],
        buckets: &[f64],
        value: f64,
    ) {
        let mut guard = self.families.lock();
        let family = guard.entry(name.to_string()).or_insert_with(|| Family {
            help: help.to_string(),
            kind: Kind::Histogram,
            samples: Vec::new(),
        });
        family.kind = Kind::Histogram;
        if family.help.is_empty() {
            family.help = help.to_string();
        }

        let mut labels_map = BTreeMap::new();
        for (k, v) in labels {
            labels_map.insert((*k).to_string(), (*v).to_string());
        }

        let known = family.samples.iter().any(|s| s.labels == labels_map);
        if !known && family.samples.len() >= MAX_SERIES_PER_FAMILY {
            self.dropped_series.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let sample = family.samples.iter_mut().find(|s| s.labels == labels_map);
        let sample = match sample {
            Some(s) => s,
            None => {
                family.samples.push(Sample {
                    labels: labels_map,
                    value: 0.0,
                    histogram: buckets.iter().map(|b| (*b, 0u64)).collect(),
                    hist_count: 0,
                    hist_sum: 0.0,
                });
                family.samples.last_mut().expect("just pushed")
            }
        };

        for (bound, count) in sample.histogram.iter_mut() {
            if value <= *bound {
                *count += 1;
            }
        }
        sample.hist_count += 1;
        sample.hist_sum += value;
    }

    fn upsert(
        &self,
        name: &str,
        help: &str,
        kind: Kind,
        labels: &[(&str, &str)],
        mutate: impl FnOnce(&mut f64),
    ) {
        let mut guard = self.families.lock();
        let family = guard.entry(name.to_string()).or_insert_with(|| Family {
            help: help.to_string(),
            kind,
            samples: Vec::new(),
        });

        // If a caller re-registers the same name with a different kind, the
        // last write wins on help+kind; treat it as developer error in tests.
        if family.kind != kind {
            family.kind = kind;
        }
        if family.help.is_empty() {
            family.help = help.to_string();
        }

        let mut labels_map = BTreeMap::new();
        for (k, v) in labels {
            labels_map.insert((*k).to_string(), (*v).to_string());
        }
        if let Some(s) = family.samples.iter_mut().find(|s| s.labels == labels_map) {
            mutate(&mut s.value);
            return;
        }
        if family.samples.len() >= MAX_SERIES_PER_FAMILY {
            self.dropped_series.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let mut s = Sample {
            labels: labels_map,
            value: 0.0,
            histogram: Vec::new(),
            hist_count: 0,
            hist_sum: 0.0,
        };
        mutate(&mut s.value);
        family.samples.push(s);
    }

    /// Render the registry into Prometheus text-format bytes.
    ///
    /// The output is deterministic for a given state: families are sorted by
    /// name and samples by labels.
    pub fn render(&self) -> String {
        // Collectors set gauges through the normal API, so run them before
        // taking the family lock (they re-enter `set_gauge`).
        let collectors: Vec<Collector> = self.collectors.lock().clone();
        for c in &collectors {
            c(self);
        }
        let guard = self.families.lock();
        let mut out = String::new();
        for (name, family) in guard.iter() {
            out.push_str("# HELP ");
            out.push_str(name);
            out.push(' ');
            out.push_str(&escape_help(&family.help));
            out.push('\n');
            out.push_str("# TYPE ");
            out.push_str(name);
            out.push(' ');
            out.push_str(family.kind.as_str());
            out.push('\n');
            let mut samples = family.samples.clone();
            samples.sort_by(|a, b| a.labels.cmp(&b.labels));
            for s in samples {
                if family.kind == Kind::Histogram {
                    render_histogram_sample(&mut out, name, &s);
                    continue;
                }
                out.push_str(name);
                if !s.labels.is_empty() {
                    out.push('{');
                    let mut first = true;
                    for (k, v) in &s.labels {
                        if !first {
                            out.push(',');
                        }
                        first = false;
                        out.push_str(k);
                        out.push_str("=\"");
                        out.push_str(&escape_label(v));
                        out.push('"');
                    }
                    out.push('}');
                }
                out.push(' ');
                // Plain decimal — Prometheus accepts floats with no exponent.
                out.push_str(&format_value(s.value));
                out.push('\n');
            }
        }
        let dropped = self.dropped_series();
        if dropped > 0 {
            out.push_str(&format!(
                "# HELP {DROPPED_SERIES_METRIC} Samples dropped because a metric family reached its label-set cap\n\
                 # TYPE {DROPPED_SERIES_METRIC} counter\n{DROPPED_SERIES_METRIC} {dropped}\n"
            ));
        }
        out
    }
}

/// Render the `_bucket{le="..."}`, `_sum`, `_count` lines for one
/// histogram sample.
fn render_histogram_sample(out: &mut String, name: &str, s: &Sample) {
    let push_labels = |out: &mut String, extra: Option<(&str, &str)>| {
        let has_any = !s.labels.is_empty() || extra.is_some();
        if !has_any {
            return;
        }
        out.push('{');
        let mut first = true;
        for (k, v) in &s.labels {
            if !first {
                out.push(',');
            }
            first = false;
            out.push_str(k);
            out.push_str("=\"");
            out.push_str(&escape_label(v));
            out.push('"');
        }
        if let Some((k, v)) = extra {
            if !first {
                out.push(',');
            }
            out.push_str(k);
            out.push_str("=\"");
            out.push_str(&escape_label(v));
            out.push('"');
        }
        out.push('}');
    };

    for (bound, count) in &s.histogram {
        out.push_str(name);
        out.push_str("_bucket");
        push_labels(out, Some(("le", &format_value(*bound))));
        out.push(' ');
        out.push_str(&count.to_string());
        out.push('\n');
    }
    // +Inf bucket — cumulative count
    out.push_str(name);
    out.push_str("_bucket");
    push_labels(out, Some(("le", "+Inf")));
    out.push(' ');
    out.push_str(&s.hist_count.to_string());
    out.push('\n');

    out.push_str(name);
    out.push_str("_sum");
    push_labels(out, None);
    out.push(' ');
    out.push_str(&format_value(s.hist_sum));
    out.push('\n');

    out.push_str(name);
    out.push_str("_count");
    push_labels(out, None);
    out.push(' ');
    out.push_str(&s.hist_count.to_string());
    out.push('\n');
}

fn escape_help(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\n', "\\n")
}

fn escape_label(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn format_value(v: f64) -> String {
    if v.fract() == 0.0 && v.is_finite() {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_increments_accumulate() {
        let r = Registry::new();
        r.inc_counter("foo_total", "Foo events", &[], 1.0);
        r.inc_counter("foo_total", "Foo events", &[], 4.5);
        let out = r.render();
        assert!(out.contains("# TYPE foo_total counter"));
        assert!(out.contains("foo_total 5"), "got: {out}");
    }

    #[test]
    fn gauge_overrides_previous_value() {
        let r = Registry::new();
        r.set_gauge("temp_celsius", "ambient temp", &[("room", "lab")], 21.5);
        r.set_gauge("temp_celsius", "ambient temp", &[("room", "lab")], 22.0);
        let out = r.render();
        assert!(out.contains("# TYPE temp_celsius gauge"));
        assert!(out.contains("temp_celsius{room=\"lab\"} 22"), "got: {out}");
    }

    #[test]
    fn multiple_label_sets_kept_separate() {
        let r = Registry::new();
        r.inc_counter("hits", "Hits per tier", &[("tier", "1")], 3.0);
        r.inc_counter("hits", "Hits per tier", &[("tier", "2")], 7.0);
        let out = r.render();
        assert!(out.contains("hits{tier=\"1\"} 3"));
        assert!(out.contains("hits{tier=\"2\"} 7"));
    }

    #[test]
    fn label_escaping_handles_quotes_and_backslashes() {
        let r = Registry::new();
        r.set_gauge("event", "any", &[("msg", r#"a"b\c"#)], 1.0);
        let out = r.render();
        assert!(out.contains(r#"event{msg="a\"b\\c"} 1"#), "got: {out}");
    }

    #[test]
    fn render_is_deterministic() {
        let r = Registry::new();
        r.inc_counter("b_total", "later", &[], 2.0);
        r.inc_counter("a_total", "earlier", &[], 1.0);
        let out = r.render();
        let a = out.find("a_total").unwrap();
        let b = out.find("b_total").unwrap();
        assert!(a < b, "families must render in alphabetical order: {out}");
    }

    /// Histogram buckets are cumulative — `_bucket{le="0.5"}` counts every
    /// observation `≤ 0.5`, including those that also fall into smaller
    /// buckets.
    #[test]
    fn histogram_buckets_are_cumulative() {
        let r = Registry::new();
        let buckets = [0.1, 0.5, 1.0, 5.0];
        for v in [0.05, 0.2, 0.7, 1.5] {
            r.observe_histogram("lat_seconds", "latency", &[], &buckets, v);
        }
        let out = r.render();
        assert!(out.contains("# TYPE lat_seconds histogram"));
        // 0.05 falls in all four declared buckets; 0.2 in {0.5, 1, 5};
        // 0.7 in {1, 5}; 1.5 in {5}.
        assert!(
            out.contains("lat_seconds_bucket{le=\"0.1\"} 1"),
            "got: {out}"
        );
        assert!(
            out.contains("lat_seconds_bucket{le=\"0.5\"} 2"),
            "got: {out}"
        );
        assert!(out.contains("lat_seconds_bucket{le=\"1\"} 3"), "got: {out}");
        assert!(out.contains("lat_seconds_bucket{le=\"5\"} 4"), "got: {out}");
        assert!(
            out.contains("lat_seconds_bucket{le=\"+Inf\"} 4"),
            "got: {out}"
        );
        assert!(out.contains("lat_seconds_count 4"), "got: {out}");
        // sum = 0.05 + 0.2 + 0.7 + 1.5 = 2.45
        assert!(
            out.contains("lat_seconds_sum 2.45"),
            "expected sum 2.45 in: {out}"
        );
    }

    #[test]
    fn histogram_label_preserved_on_bucket_lines() {
        let r = Registry::new();
        let buckets = [1.0, 10.0];
        r.observe_histogram("rpc_dur", "dur", &[("method", "ping")], &buckets, 0.5);
        let out = r.render();
        assert!(
            out.contains(r#"rpc_dur_bucket{method="ping",le="1"} 1"#),
            "got: {out}"
        );
        assert!(
            out.contains(r#"rpc_dur_count{method="ping"} 1"#),
            "got: {out}"
        );
    }
}
