//! `entangle logs` — read the daemon's per-plugin and per-subsystem log
//! buffers (spec §9.6).
//!
//! ```text
//! entangle logs hello-world                      # the last lines the plugin printed
//! entangle logs scheduler --filter StalledEvent  # stalled streams (spec §7.1)
//! entangle logs mesh --level warn --since 10m
//! entangle logs daemon --follow --json
//! ```
//!
//! The source is `scheduler`, `mesh`, `gateway`, `daemon`, or a plugin: its
//! full id or its name when that is unambiguous. The buffers live in the
//! daemon's memory (see `[logs]` in `docs/operations.md`): they start empty
//! when the daemon starts and hold the most recent lines only. Secrets are
//! redacted before they are stored.
//!
//! `--follow` long-polls the daemon (each request is held open up to 25 s)
//! and ends cleanly on Ctrl-C.

use clap::Args;
use entangle_rpc::methods::{LogLineWire, LogsReadParams, LogsReadResult};
use entangle_rpc::{Client as RpcClient, RpcError};
use std::borrow::Cow;
use std::io::Write as _;
use std::time::Duration;

use crate::daemon_not_running_error;

/// How long each follow request is held open by the daemon.
const FOLLOW_WAIT_MS: u64 = 25_000;
/// Lines shown by default.
const DEFAULT_TAIL: usize = 100;

/// Arguments of `entangle logs`.
#[derive(Args)]
pub struct LogsArgs {
    /// `scheduler`, `mesh`, `gateway`, `daemon`, or a plugin (full id, or its name).
    pub source: String,
    /// Keep waiting for new lines until interrupted (Ctrl-C).
    #[arg(long, short = 'f')]
    pub follow: bool,
    /// Only lines whose event name equals this (e.g. `StalledEvent`) or whose
    /// message, target or a field contains it (case-insensitive).
    #[arg(long)]
    pub filter: Option<String>,
    /// Only lines at or above this level: trace, debug, info, warn, error.
    #[arg(long)]
    pub level: Option<String>,
    /// Only lines newer than this long ago: `90s`, `10m`, `2h`, `1d` (or `500ms`).
    #[arg(long)]
    pub since: Option<String>,
    /// How many of the newest matching lines to show first.
    #[arg(long, short = 'n', default_value_t = DEFAULT_TAIL)]
    pub tail: usize,
    /// One JSON object per line instead of text.
    #[arg(long)]
    pub json: bool,
}

/// Parse `90s`, `10m`, `2h`, `1d`, `500ms` (a bare number is seconds).
pub fn parse_duration(s: &str) -> anyhow::Result<Duration> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration '{s}': expected e.g. 90s, 10m, 2h, 1d"))?;
    let ms_per = match unit.trim() {
        "ms" => 1,
        "" | "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        other => {
            anyhow::bail!("invalid duration '{s}': unknown unit '{other}' (use ms, s, m, h, d)")
        }
    };
    n.checked_mul(ms_per)
        .map(Duration::from_millis)
        .ok_or_else(|| anyhow::anyhow!("duration '{s}' is too large"))
}

/// `2026-11-04T15:56:34.719Z` for a Unix time in milliseconds.
pub fn format_timestamp(unix_ms: u64) -> String {
    let secs = (unix_ms / 1000) as i64;
    let ms = unix_ms % 1000;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{ms:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// `s` with every control character but tab escaped (`\n`, `\r`,
/// `\u{1b}`, C1 controls such as `\u{9b}`, DEL): text a plugin printed goes
/// to the operator's terminal, where an ESC or CSI sequence would run (move
/// the cursor, erase lines, set the clipboard) and a newline would let it
/// forge a log line. Text without control characters is returned as is.
pub fn escape_controls(s: &str) -> Cow<'_, str> {
    if !s.chars().any(|c| c.is_control() && c != '\t') {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if c.is_control() && c != '\t' {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// One line as text:
/// `2026-11-04T15:56:34.719Z WARN  entangle::scheduler::stream [StalledEvent] message k=v`.
///
/// Every part that can carry text a plugin chose is passed through
/// [`escape_controls`] (values with whitespace are quoted with Rust's
/// escaping), so one buffered line is one terminal line.
pub fn format_line(l: &LogLineWire) -> String {
    let mut out = format!(
        "{} {:<5}",
        format_timestamp(l.unix_ms),
        escape_controls(&l.level.to_uppercase())
    );
    // Plugin output is already filed under its plugin: the target adds nothing.
    if l.target != "entangle::plugin" && l.target != "entangle::native" {
        out.push(' ');
        out.push_str(&escape_controls(&l.target));
    }
    if let Some(e) = &l.event {
        out.push_str(&format!(" [{}]", escape_controls(e)));
    }
    if !l.message.is_empty() {
        out.push(' ');
        out.push_str(&escape_controls(&l.message));
    }
    for (k, v) in &l.fields {
        let k = escape_controls(k);
        if v.contains(char::is_whitespace) {
            out.push_str(&format!(" {k}={v:?}"));
        } else {
            out.push_str(&format!(" {k}={}", escape_controls(v)));
        }
    }
    out
}

fn rpc_error(e: RpcError) -> anyhow::Error {
    match e {
        RpcError::DaemonNotRunning(_) => daemon_not_running_error(),
        // The daemon's message already starts with its ENTANGLE code.
        RpcError::Rpc { message, .. } => anyhow::anyhow!(message),
        e => e.into(),
    }
}

/// Write `lines` to stdout; `Ok(false)` when stdout was closed (`| head`).
fn print_lines(lines: &[LogLineWire], json: bool) -> anyhow::Result<bool> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for l in lines {
        let text = if json {
            serde_json::to_string(l)?
        } else {
            format_line(l)
        };
        match writeln!(out, "{text}") {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => return Ok(false),
            Err(e) => return Err(e.into()),
        }
    }
    match out.flush() {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn note_truncation(r: &LogsReadResult) {
    if r.truncated {
        eprintln!("-- some older lines were dropped from the daemon's buffer before they could be read --");
    }
}

/// Run `entangle logs`.
pub async fn run(a: LogsArgs) -> anyhow::Result<()> {
    run_with(a, RpcClient::new(RpcClient::default_socket())).await
}

pub(crate) async fn run_with(a: LogsArgs, client: RpcClient) -> anyhow::Result<()> {
    let since_ms = a
        .since
        .as_deref()
        .map(|s| parse_duration(s).map(|d| d.as_millis() as u64))
        .transpose()?;
    if a.tail == 0 {
        anyhow::bail!("--tail must be at least 1");
    }
    let base = LogsReadParams {
        source: a.source.clone(),
        level: a.level.clone(),
        filter: a.filter.clone(),
        since_ms,
        limit: Some(a.tail),
        ..Default::default()
    };
    let first = client.logs_read(base.clone()).await.map_err(rpc_error)?;
    if !print_lines(&first.lines, a.json)? || !a.follow {
        return Ok(());
    }
    let mut cursor = first.next_cursor;
    let follow = async {
        loop {
            let page = client
                .logs_read(LogsReadParams {
                    after: Some(cursor),
                    wait_ms: Some(FOLLOW_WAIT_MS),
                    limit: None,
                    // `--since` bounds the first page only.
                    since_ms: None,
                    ..base.clone()
                })
                .await
                .map_err(|e| match e {
                    RpcError::Io(_) | RpcError::Malformed(_) => {
                        anyhow::anyhow!("lost the connection to the daemon while following: {e}")
                    }
                    e => rpc_error(e),
                })?;
            note_truncation(&page);
            if !print_lines(&page.lines, a.json)? {
                return Ok(());
            }
            cursor = page.next_cursor;
        }
    };
    tokio::select! {
        r = follow => r,
        // Ctrl-C ends the follow cleanly (exit status 0, nothing half-written).
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("10m").unwrap(), Duration::from_secs(600));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86_400));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("30").unwrap(), Duration::from_secs(30));
        for bad in ["", "m", "10x", "-5s", "1.5h", "99999999999999999999s"] {
            assert!(parse_duration(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn timestamps() {
        assert_eq!(format_timestamp(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            format_timestamp(1_793_807_794_790),
            "2026-11-04T15:56:34.790Z"
        );
        // Leap day and the century rule.
        assert_eq!(
            format_timestamp(951_782_400_000),
            "2000-02-29T00:00:00.000Z"
        );
        assert_eq!(
            format_timestamp(1_709_164_800_000),
            "2024-02-29T00:00:00.000Z"
        );
    }

    #[test]
    fn text_lines() {
        let l = LogLineWire {
            seq: 1,
            unix_ms: 0,
            level: "warn".into(),
            target: "entangle::scheduler::stream".into(),
            event: Some("StalledEvent".into()),
            message: "stream stalled".into(),
            fields: vec![("task".into(), "t1".into()), ("note".into(), "a b".into())],
        };
        assert_eq!(
            format_line(&l),
            "1970-01-01T00:00:00.000Z WARN  entangle::scheduler::stream [StalledEvent] stream stalled task=t1 note=\"a b\""
        );
        let out = LogLineWire {
            target: "entangle::plugin".into(),
            event: None,
            level: "info".into(),
            message: "hello".into(),
            fields: vec![("stream".into(), "stdout".into())],
            ..l
        };
        assert_eq!(
            format_line(&out),
            "1970-01-01T00:00:00.000Z INFO  hello stream=stdout"
        );
    }

    /// Text a plugin printed reaches the terminal escaped: no line it can
    /// forge, no escape sequence the terminal would run.
    #[test]
    fn plugin_controlled_text_cannot_drive_the_terminal() {
        let l = LogLineWire {
            seq: 1,
            unix_ms: 0,
            level: "info".into(),
            target: "entangle::plugin".into(),
            event: Some("ev\x1b[31m".into()),
            message:
                "ok\n2026-11-04T15:56:34.719Z WARN  entangle_runtime::kernel capability granted\
                      \x1b]52;c;aGk=\x07\r\x1b[1A\x1b[2K\u{9b}31m\u{7f}\ttab"
                    .into(),
            fields: vec![
                ("stream".into(), "stdout\x1b[2J".into()),
                ("note".into(), "a\x1b[1A b".into()),
            ],
        };
        let text = format_line(&l);
        assert!(
            !text.chars().any(|c| c.is_control() && c != '\t'),
            "{text:?}"
        );
        assert!(
            text.contains(
                "ok\\n2026-11-04T15:56:34.719Z WARN  entangle_runtime::kernel capability granted"
            ),
            "{text}"
        );
        assert!(
            text.contains("\\u{1b}]52;c;aGk=\\u{7}\\r\\u{1b}[1A\\u{1b}[2K\\u{9b}31m\\u{7f}\ttab"),
            "{text}"
        );
        assert!(text.contains(" stream=stdout\\u{1b}[2J"), "{text}");
        assert!(text.contains(" note=\"a\\u{1b}[1A b\""), "{text}");
        assert!(text.contains("[ev\\u{1b}[31m]"), "{text}");
        // Ordinary text (non-ASCII, tabs) is passed through untouched.
        assert!(matches!(
            escape_controls("café\tok ✓"),
            Cow::Borrowed("café\tok ✓")
        ));
    }
}
