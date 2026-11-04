//! Plugin output as `tracing` events, for `entangle logs <plugin-id>`.
//!
//! Everything a wasm plugin prints reaches the daemon's log pipeline as an
//! event with target [`TARGET`] and a `plugin` field, which the daemon's log
//! buffer files under that plugin only:
//!
//! * the guest `log` import ([`crate::bindings`]) via [`emit_line`] with
//!   `stream = "log"` and the level the guest chose;
//! * WASI stdout and stderr via [`CapturedOutput`], which splits the byte
//!   stream into lines (`stream = "stdout"` / `"stderr"`, level `INFO`).
//!
//! Before this module stdout was discarded and stderr went to the daemon's
//! own stderr, mixed with every other plugin's.
//!
//! # Bounds
//!
//! One [`CapturedOutput`] (one instance's stdout and stderr together) emits
//! at most [`MAX_LINES`] lines and [`MAX_BYTES`] bytes, each line cut to
//! [`MAX_LINE_BYTES`]; past that it keeps accepting writes (the guest must
//! not see an error) but drops the data after one warning line.

use entangle_types::plugin_id::PluginId;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::AsyncWrite;
use wasmtime_wasi::cli::{IsTerminal, StdoutStream};

/// `tracing` target of plugin output events.
pub const TARGET: &str = "entangle::plugin";
/// Most lines one captured instance emits.
pub const MAX_LINES: usize = 1_000;
/// Most bytes one captured instance emits.
pub const MAX_BYTES: usize = 256 * 1024;
/// Longest single line emitted; the rest of a longer line is dropped.
pub const MAX_LINE_BYTES: usize = 4096;

/// Emit one line of plugin output at the level a guest `log` call named
/// (`trace`, `debug`, `info`, `warn`, `error`; anything else is `info`).
pub fn emit_line(plugin: &PluginId, level: &str, stream: &str, text: &str) {
    let plugin = plugin.to_string();
    match level {
        "trace" => tracing::trace!(target: TARGET, plugin = %plugin, stream, "{text}"),
        "debug" => tracing::debug!(target: TARGET, plugin = %plugin, stream, "{text}"),
        "warn" => tracing::warn!(target: TARGET, plugin = %plugin, stream, "{text}"),
        "error" => tracing::error!(target: TARGET, plugin = %plugin, stream, "{text}"),
        _ => tracing::info!(target: TARGET, plugin = %plugin, stream, "{text}"),
    }
}

struct Budget {
    plugin: PluginId,
    lines: AtomicUsize,
    bytes: AtomicUsize,
}

impl Budget {
    /// Emit `line` if the budget allows; the first refusal emits a marker.
    fn emit(&self, stream: &'static str, line: &[u8]) {
        let text = String::from_utf8_lossy(line);
        let text = text.trim_end_matches(['\r', '\n']);
        if text.is_empty() {
            return;
        }
        let n = self.lines.fetch_add(1, Ordering::Relaxed);
        let clipped = clip(text);
        let used = self.bytes.fetch_add(clipped.len(), Ordering::Relaxed);
        if n < MAX_LINES && used + clipped.len() <= MAX_BYTES {
            emit_line(&self.plugin, "info", stream, clipped);
        } else if n == MAX_LINES || (used <= MAX_BYTES && used + clipped.len() > MAX_BYTES) {
            emit_line(
                &self.plugin,
                "warn",
                stream,
                &format!(
                    "[output truncated: more than {MAX_LINES} lines or {MAX_BYTES} bytes in one invocation]"
                ),
            );
        }
    }
}

fn clip(s: &str) -> &str {
    if s.len() <= MAX_LINE_BYTES {
        return s;
    }
    let mut cut = MAX_LINE_BYTES;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    &s[..cut]
}

/// A WASI stdout/stderr replacement that turns the byte stream into log
/// events. Build one per stream with [`CapturedOutput::pair`].
#[derive(Clone)]
pub struct CapturedOutput {
    stream: &'static str,
    budget: Arc<Budget>,
    partial: Arc<Mutex<Vec<u8>>>,
}

impl CapturedOutput {
    /// The stdout and stderr capture of one instance, sharing one budget.
    pub fn pair(plugin: &PluginId) -> (Self, Self) {
        let budget = Arc::new(Budget {
            plugin: plugin.clone(),
            lines: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
        });
        let mk = |stream| Self {
            stream,
            budget: Arc::clone(&budget),
            partial: Arc::default(),
        };
        (mk("stdout"), mk("stderr"))
    }

    fn feed(&self, data: &[u8]) {
        let Ok(mut partial) = self.partial.lock() else {
            return;
        };
        for &b in data {
            if b == b'\n' {
                self.budget.emit(self.stream, &partial);
                partial.clear();
            } else if partial.len() < MAX_LINE_BYTES {
                partial.push(b);
            }
            // Bytes past MAX_LINE_BYTES of one line are dropped.
        }
    }

    fn flush_partial(&self) {
        if let Ok(mut partial) = self.partial.lock() {
            if !partial.is_empty() {
                self.budget.emit(self.stream, &partial);
                partial.clear();
            }
        }
    }
}

impl Drop for CapturedOutput {
    fn drop(&mut self) {
        // The last handle's drop emits an unterminated final line.
        if Arc::strong_count(&self.partial) == 1 {
            self.flush_partial();
        }
    }
}

impl IsTerminal for CapturedOutput {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdoutStream for CapturedOutput {
    fn async_stream(&self) -> Box<dyn AsyncWrite + Send + Sync> {
        Box::new(self.clone())
    }
}

impl AsyncWrite for CapturedOutput {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.feed(buf);
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flush_partial();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use tracing::field::{Field, Visit};
    use tracing_subscriber::prelude::*;

    #[derive(Default, Clone)]
    struct Sink(Arc<StdMutex<Vec<(String, String, String)>>>);

    struct V(String, String, String);
    impl Visit for V {
        fn record_str(&mut self, f: &Field, v: &str) {
            if f.name() == "stream" {
                self.2 = v.to_owned();
            }
        }
        fn record_debug(&mut self, f: &Field, v: &dyn std::fmt::Debug) {
            match f.name() {
                "message" => self.0 = format!("{v:?}"),
                "plugin" => self.1 = format!("{v:?}"),
                _ => {}
            }
        }
    }
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Sink {
        fn on_event(&self, e: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
            if e.metadata().target() == TARGET {
                let mut v = V(String::new(), String::new(), String::new());
                e.record(&mut v);
                self.0.lock().unwrap().push((v.0, v.1, v.2));
            }
        }
    }

    fn id() -> PluginId {
        "aabbccddeeff00112233445566778899/out-test@0.1.0"
            .parse()
            .unwrap()
    }

    fn capture<R>(f: impl FnOnce() -> R) -> (R, Vec<(String, String, String)>) {
        let sink = Sink::default();
        let sub = tracing_subscriber::registry().with(sink.clone());
        let r = tracing::subscriber::with_default(sub, f);
        let lines = sink.0.lock().unwrap().clone();
        (r, lines)
    }

    #[test]
    fn lines_are_split_tagged_and_the_tail_is_flushed_on_drop() {
        let (_, lines) = capture(|| {
            let (out, err) = CapturedOutput::pair(&id());
            out.feed(b"one\ntw");
            out.feed(b"o\r\n\n");
            err.feed(b"oops\nunterminated");
            drop(out);
            drop(err);
        });
        let got: Vec<(&str, &str)> = lines
            .iter()
            .map(|(m, _, s)| (m.as_str(), s.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("one", "stdout"),
                ("two", "stdout"),
                ("oops", "stderr"),
                ("unterminated", "stderr")
            ]
        );
        assert!(lines[0].1.contains("out-test@0.1.0"));
    }

    #[test]
    fn output_is_bounded_per_instance_with_one_marker_and_never_errors() {
        let (_, lines) = capture(|| {
            let (out, _err) = CapturedOutput::pair(&id());
            for i in 0..(MAX_LINES + 500) {
                out.feed(format!("line {i}\n").as_bytes());
            }
            // A very long line is clipped.
            out.feed("x".repeat(MAX_LINE_BYTES * 3).as_bytes());
            out.feed(b"\n");
        });
        assert_eq!(lines.len(), MAX_LINES + 1, "cap plus one marker");
        assert!(lines.last().unwrap().0.contains("output truncated"));
        assert_eq!(
            lines
                .iter()
                .filter(|l| l.0.contains("output truncated"))
                .count(),
            1
        );
    }

    #[test]
    fn guest_log_levels_map_to_tracing_levels() {
        let (_, lines) = capture(|| {
            emit_line(&id(), "warn", "log", "careful");
            emit_line(&id(), "bogus", "log", "fallback");
        });
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].2, "log");
    }
}
