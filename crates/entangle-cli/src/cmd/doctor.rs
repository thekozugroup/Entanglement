//! `entangle doctor` — structured pre-flight health checks (spec §9.2).
//!
//! Prints one line per check with `[ok] / [warn] / [fail] / [skip]`.
//! Exit code 0 if no `fail`; exit code 1 if any `fail`.  `warn` does not fail.

use std::path::Path;

use is_terminal::IsTerminal as _;

use crate::config::{self, entangle_dir};
use entangle_peers::PeerStore;
use entangle_signing::{IdentityKeyPair, Keyring};

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// The outcome of a single doctor check.
pub struct CheckResult {
    /// Short stable name (shown in the output column).
    pub name: &'static str,
    /// Pass/warn/fail/skip, carrying the human-readable reason.
    pub status: Status,
    /// Additional context printed after the status message.
    pub detail: String,
}

/// Status of a single doctor check.
pub enum Status {
    /// Check passed.
    Ok,
    /// Non-fatal issue; printed in yellow.
    Warn(String),
    /// Fatal issue; printed in red; increments exit-code counter.
    Fail(String),
    /// Check was not applicable and was skipped.
    Skip(String),
}

impl CheckResult {
    fn ok(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Ok,
            detail: detail.into(),
        }
    }
    fn warn(name: &'static str, msg: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Warn(msg.into()),
            detail: detail.into(),
        }
    }
    fn fail(name: &'static str, msg: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Fail(msg.into()),
            detail: detail.into(),
        }
    }
    fn skip(name: &'static str, reason: impl Into<String>) -> Self {
        let r = reason.into();
        Self {
            name,
            status: Status::Skip(r.clone()),
            detail: r,
        }
    }
}

// ---------------------------------------------------------------------------
// Check 1 — identity
// ---------------------------------------------------------------------------

fn check_identity() -> CheckResult {
    let path = config::identity_path();
    if !path.exists() {
        return CheckResult::fail(
            "identity",
            "missing",
            format!("{} not found — run `entangle init`", path.display()),
        );
    }
    match std::fs::read_to_string(&path) {
        Err(e) => CheckResult::fail("identity", "io error", format!("cannot read: {e}")),
        Ok(pem) => match IdentityKeyPair::from_pem(&pem) {
            Err(e) => CheckResult::fail("identity", "corrupt", format!("PEM parse failed: {e}")),
            Ok(kp) => {
                let fp = kp.fingerprint_hex();
                let fp_display = chunks_4(&fp).join("-");
                CheckResult::ok("identity", format!("Ed25519 keypair, fp {fp_display}"))
            }
        },
    }
}

// ---------------------------------------------------------------------------
// Check 2 — identity-perms
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn check_identity_perms() -> CheckResult {
    use std::os::unix::fs::MetadataExt;
    let path = config::identity_path();
    if !path.exists() {
        return CheckResult::skip("identity-perms", "identity.key absent");
    }
    match std::fs::metadata(&path) {
        Err(e) => CheckResult::warn(
            "identity-perms",
            "cannot stat",
            format!("could not stat identity.key: {e}"),
        ),
        Ok(meta) => {
            let mode = meta.mode() & 0o777;
            // Warn if any group/other bit is set (should be 0600).
            if mode & 0o177 != 0 {
                CheckResult::warn(
                    "identity-perms",
                    format!("mode {:04o} — world/group readable", mode),
                    format!("consider: chmod 600 {}", path.display()),
                )
            } else {
                CheckResult::ok("identity-perms", format!("mode {:04o}", mode))
            }
        }
    }
}

#[cfg(not(unix))]
fn check_identity_perms() -> CheckResult {
    CheckResult::skip(
        "identity-perms",
        "permission check not supported on this OS",
    )
}

// ---------------------------------------------------------------------------
// Check 3 — config
// ---------------------------------------------------------------------------

fn check_config() -> CheckResult {
    let path = config::config_path();
    if !path.exists() {
        return CheckResult::warn(
            "config",
            "not present (using defaults)",
            format!("{} absent", path.display()),
        );
    }
    match config::load(&path) {
        Ok(_) => CheckResult::ok("config", path.display().to_string()),
        Err(e) => CheckResult::fail("config", "parse error", format!("{e}")),
    }
}

// ---------------------------------------------------------------------------
// Check 4 — keyring
// ---------------------------------------------------------------------------

fn check_keyring() -> CheckResult {
    let path = config::keyring_path();
    if !path.exists() {
        return CheckResult::ok(
            "keyring",
            "0 trusted publishers (absent — ok for single-user)",
        );
    }
    match Keyring::load(&path) {
        Err(e) => CheckResult::fail("keyring", "parse error", format!("{e}")),
        Ok(kr) => {
            let count = kr.entries().count();
            CheckResult::ok("keyring", format!("{count} trusted publisher(s)"))
        }
    }
}

// ---------------------------------------------------------------------------
// Check 5 — peers
// ---------------------------------------------------------------------------

fn check_peers() -> CheckResult {
    let peers_path = entangle_dir().join("peers.toml");
    let cfg = config::load(&config::config_path()).unwrap_or_default();

    let multi_node = cfg.mesh.multi_node;

    if !peers_path.exists() {
        if multi_node {
            return CheckResult::warn(
                "peers",
                "multi_node enabled but peers.toml absent",
                "daemon will refuse to start — run `entangle pair` to add peers",
            );
        }
        return CheckResult::ok("peers", "absent (single-node mode)");
    }

    match PeerStore::open(&peers_path) {
        Err(e) => CheckResult::fail("peers", "parse error", format!("{e}")),
        Ok(store) => {
            let n = store.len();
            if multi_node && store.is_empty() {
                CheckResult::warn(
                    "peers",
                    "multi_node enabled but peers.toml empty",
                    "daemon will refuse to start — run `entangle pair` to add peers",
                )
            } else {
                CheckResult::ok("peers", format!("{n} trusted peer(s)"))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Check 6 — dir-perms
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn check_dir_perms() -> CheckResult {
    use std::os::unix::fs::MetadataExt;
    let dir = entangle_dir();
    if !dir.exists() {
        return CheckResult::skip("dir-perms", "~/.entangle/ absent");
    }
    match std::fs::metadata(&dir) {
        Err(e) => CheckResult::warn(
            "dir-perms",
            "cannot stat",
            format!("could not stat dir: {e}"),
        ),
        Ok(meta) => {
            let mode = meta.mode() & 0o777;
            if mode & 0o077 != 0 {
                CheckResult::warn(
                    "dir-perms",
                    format!("mode {:04o} — others have access", mode),
                    format!("consider: chmod 700 {}", dir.display()),
                )
            } else {
                CheckResult::ok("dir-perms", format!("mode {:04o}", mode))
            }
        }
    }
}

#[cfg(not(unix))]
fn check_dir_perms() -> CheckResult {
    CheckResult::skip("dir-perms", "permission check not supported on this OS")
}

// ---------------------------------------------------------------------------
// Check 7 — rust-toolchain
// ---------------------------------------------------------------------------

fn check_rust_toolchain() -> CheckResult {
    // RUSTC_VERSION may be injected by a build script; fall back to shelling out.
    let v = option_env!("RUSTC_VERSION")
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            std::process::Command::new("rustc")
                .arg("--version")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .unwrap_or_else(|| "unknown".into())
                .trim()
                .to_string()
        });
    CheckResult::ok("rust-toolchain", v)
}

// ---------------------------------------------------------------------------
// Check 8 — wasm32-wasip2
// ---------------------------------------------------------------------------

fn check_wasm_target() -> CheckResult {
    let out = std::process::Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output();
    match out {
        Err(_) => CheckResult::warn(
            "wasm32-wasip2",
            "rustup not found",
            "install rustup to build Wasm plugins",
        ),
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if stdout.contains("wasm32-wasip2") {
                CheckResult::ok("wasm32-wasip2", "installed")
            } else {
                CheckResult::warn(
                    "wasm32-wasip2",
                    "not installed",
                    "run: rustup target add wasm32-wasip2",
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Checks 9 & 10 — daemon-reachable + daemon-version-match
// ---------------------------------------------------------------------------

async fn check_daemon() -> (CheckResult, CheckResult) {
    let socket = entangle_rpc::Client::default_socket();
    let client = entangle_rpc::Client::new(&socket);
    let cli_version = env!("CARGO_PKG_VERSION");

    let version_result = client.version().await;
    match version_result {
        Err(ref e) if !socket.exists() => {
            let _ = e; // suppress unused-var warning
            let reachable = CheckResult::warn(
                "daemon-reachable",
                "not running (start with `entangled run`)",
                format!("socket {} absent", socket.display()),
            );
            let vm = CheckResult::skip("daemon-version-match", "skipped (daemon not reachable)");
            (reachable, vm)
        }
        Err(e) => {
            let reachable =
                CheckResult::warn("daemon-reachable", "connection error", format!("{e}"));
            let vm = CheckResult::skip("daemon-version-match", "skipped (daemon not reachable)");
            (reachable, vm)
        }
        Ok(v) => {
            let reachable = CheckResult::ok("daemon-reachable", format!("daemon {}", v.entangled));
            let vm = if v.entangled == cli_version {
                CheckResult::ok("daemon-version-match", format!("both {cli_version}"))
            } else {
                CheckResult::warn(
                    "daemon-version-match",
                    format!("daemon {} vs CLI {cli_version}", v.entangled),
                    "restart daemon after upgrading",
                )
            };
            (reachable, vm)
        }
    }
}

// ---------------------------------------------------------------------------
// Check 11 — OS sandbox availability
// ---------------------------------------------------------------------------

fn check_os_sandbox() -> CheckResult {
    #[cfg(target_os = "macos")]
    {
        let found = std::process::Command::new("which")
            .arg("sandbox-exec")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if found {
            return CheckResult::ok("OS sandbox", "sandbox-exec present (macOS Seatbelt)");
        } else {
            return CheckResult::warn(
                "OS sandbox",
                "sandbox-exec not found in PATH",
                "Seatbelt sandboxing unavailable; plugin isolation may be reduced",
            );
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Landlock: kernel ≥5.13 exposes /proc/sys/kernel/landlock/status == "1".
        let landlock_ok = std::fs::read_to_string("/proc/sys/kernel/landlock/status")
            .map(|s| s.trim() == "1")
            .unwrap_or(false);

        if landlock_ok {
            return CheckResult::ok("OS sandbox", "Linux Landlock available");
        }

        // Fallback: bubblewrap.
        let bwrap = std::process::Command::new("which")
            .arg("bwrap")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if bwrap {
            return CheckResult::ok(
                "OS sandbox",
                "Landlock unavailable; bubblewrap present (fallback)",
            );
        }
        return CheckResult::warn(
            "OS sandbox",
            "neither Landlock nor bubblewrap available",
            "upgrade kernel to ≥5.13 or install bubblewrap for plugin sandboxing",
        );
    }

    #[cfg(windows)]
    {
        return CheckResult::warn(
            "OS sandbox",
            "AppContainer support is Phase 5+",
            "Windows plugin sandboxing is not yet implemented",
        );
    }

    // Fallback for any other OS.
    #[allow(unreachable_code)]
    CheckResult::warn(
        "OS sandbox",
        "unknown OS — sandbox status unknown",
        "no sandbox check implemented for this platform",
    )
}

// ---------------------------------------------------------------------------
// Check 12 — disk-space
// ---------------------------------------------------------------------------

fn check_disk_space() -> CheckResult {
    let dir = entangle_dir();
    let probe = if dir.exists() {
        dir.clone()
    } else {
        std::env::temp_dir()
    };

    match free_bytes_via_df(&probe) {
        None => CheckResult::warn("disk-space", "cannot determine free space", ""),
        Some(free) => {
            let gib = free as f64 / (1024.0 * 1024.0 * 1024.0);
            if free < 1024 * 1024 * 1024 {
                CheckResult::warn(
                    "disk-space",
                    format!("{:.1} GiB free — below 1 GiB recommended", gib),
                    format!("filesystem hosting {}", probe.display()),
                )
            } else {
                CheckResult::ok("disk-space", format!("{:.1} GiB free", gib))
            }
        }
    }
}

/// Use `df -k <path>` to get free disk space — no extra crates required.
fn free_bytes_via_df(path: &Path) -> Option<u64> {
    let out = std::process::Command::new("df")
        .arg("-k")
        .arg(path)
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    // `df -k` output: header line then one data line with fields:
    // Filesystem  1K-blocks  Used  Available  Use%  Mounted (Linux)
    // Filesystem  512-blocks  Used  Available  Cap%  iused  ifree  %iused  Mounted (macOS)
    // The "Available" column is the 4th field (index 3) on both.
    let line = stdout.lines().nth(1)?;
    let avail_kib: u64 = line.split_whitespace().nth(3)?.parse().ok()?;
    Some(avail_kib * 1024)
}

// ---------------------------------------------------------------------------
// Check 13 — clock-skew
// ---------------------------------------------------------------------------

/// Clock skew requires a daemon `time()` RPC not yet implemented.
/// Skipped when daemon is unreachable; TODO when it is reachable.
fn check_clock_skew(daemon_reachable: bool) -> CheckResult {
    if !daemon_reachable {
        return CheckResult::skip("clock-skew", "skipped (daemon not reachable)");
    }
    // TODO: call daemon time() RPC when added; compare to SystemTime::now().
    // For now always skip to avoid a false-fail.
    CheckResult::skip("clock-skew", "time() RPC not yet implemented in daemon")
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

/// Split a hex string into 4-char groups for fingerprint display.
fn chunks_4(s: &str) -> Vec<&str> {
    let b = s.as_bytes();
    (0..b.len())
        .step_by(4)
        .map(|i| std::str::from_utf8(&b[i..std::cmp::min(i + 4, b.len())]).unwrap_or(""))
        .collect()
}

fn status_label(status: &Status, color: bool) -> String {
    match status {
        Status::Ok => {
            if color {
                "\x1b[32m[ok]\x1b[0m  ".into()
            } else {
                "[ok]   ".into()
            }
        }
        Status::Warn(_) => {
            if color {
                "\x1b[33m[warn]\x1b[0m".into()
            } else {
                "[warn] ".into()
            }
        }
        Status::Fail(_) => {
            if color {
                "\x1b[31m[fail]\x1b[0m".into()
            } else {
                "[fail] ".into()
            }
        }
        Status::Skip(_) => {
            if color {
                "\x1b[2m[skip]\x1b[0m".into()
            } else {
                "[skip] ".into()
            }
        }
    }
}

fn status_msg(status: &Status) -> &str {
    match status {
        Status::Ok => "",
        Status::Warn(m) | Status::Fail(m) | Status::Skip(m) => m.as_str(),
    }
}

fn print_check(c: &CheckResult, color: bool) {
    let label = status_label(&c.status, color);
    let msg = status_msg(&c.status);
    let combined = if msg.is_empty() || msg == c.detail.as_str() {
        c.detail.clone()
    } else if c.detail.is_empty() {
        msg.to_string()
    } else {
        format!("{msg} — {}", c.detail)
    };
    eprintln!("{label}  {:<24}  {combined}", c.name);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run() -> anyhow::Result<()> {
    let color = std::io::stderr().is_terminal();
    let mut results: Vec<CheckResult> = vec![
        check_identity(),
        check_identity_perms(),
        check_config(),
        check_keyring(),
        check_peers(),
        check_dir_perms(),
        check_rust_toolchain(),
        check_wasm_target(),
    ];

    let (daemon_reach, daemon_ver) = check_daemon().await;
    let daemon_reachable = matches!(daemon_reach.status, Status::Ok);
    results.push(daemon_reach);
    results.push(daemon_ver);

    results.push(check_os_sandbox());
    results.push(check_disk_space());
    results.push(check_clock_skew(daemon_reachable));

    for r in &results {
        print_check(r, color);
    }

    let mut n_ok = 0usize;
    let mut n_warn = 0usize;
    let mut n_fail = 0usize;
    let mut n_skip = 0usize;
    let mut any_fail = false;

    for r in &results {
        match &r.status {
            Status::Ok => n_ok += 1,
            Status::Warn(_) => n_warn += 1,
            Status::Fail(_) => {
                n_fail += 1;
                any_fail = true;
            }
            Status::Skip(_) => n_skip += 1,
        }
    }

    eprintln!();
    let skip_str = if n_skip > 0 {
        format!(", {n_skip} skip")
    } else {
        String::new()
    };
    eprintln!("Summary: {n_ok} ok, {n_warn} warn, {n_fail} fail{skip_str}");

    if any_fail {
        std::process::exit(1);
    }
    Ok(())
}
