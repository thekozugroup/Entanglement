//! `entangle doctor` — structured pre-flight health checks (spec §9.2).
//!
//! Prints one line per check with `[ok] / [warn] / [fail] / [skip]`.
//! Exit code 0 if no `fail`; exit code 1 if any `fail`.  `warn` does not fail.

use std::io::IsTerminal as _;
use std::path::Path;

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
// Check 11 — OS sandbox: which primitive would be engaged, and does it work
// ---------------------------------------------------------------------------

/// The operator's `[security] allow_unsandboxed_native` setting (default off).
fn sandbox_policy() -> entangle_runtime::os_sandbox::Policy {
    let allow_unsandboxed = config::load(&config::config_path())
        .map(|c| c.security.allow_unsandboxed_native)
        .unwrap_or(false);
    entangle_runtime::os_sandbox::Policy { allow_unsandboxed }
}

/// What a tier-5 plugin without network access would run under here.
fn check_os_sandbox(policy: entangle_runtime::os_sandbox::Policy) -> CheckResult {
    use entangle_runtime::os_sandbox;
    let host = os_sandbox::host_support().describe();
    match os_sandbox::plan_for(false, policy) {
        Ok(plan) if plan.is_degraded() => CheckResult::warn(
            "OS sandbox",
            format!("reduced isolation: {}", plan.describe()),
            format!("host: {host}"),
        ),
        Ok(plan) => CheckResult::ok(
            "OS sandbox",
            format!("would engage {} (host: {host})", plan.describe()),
        ),
        Err(e) => CheckResult::warn(
            "OS sandbox",
            "native (tier 4-5) plugins will be refused on this host",
            format!("{e} (host: {host})"),
        ),
    }
}

/// Engage the sandbox for real on two trivial children.
fn check_sandbox_trial(policy: entangle_runtime::os_sandbox::Policy) -> CheckResult {
    use entangle_runtime::os_sandbox::{self, TrialOutcome};
    const NAME: &str = "sandbox trial";
    match os_sandbox::trial(policy) {
        TrialOutcome::Enforced { plan } => CheckResult::ok(
            NAME,
            format!(
                "child ran under {}; a read outside its scope was denied",
                plan.describe()
            ),
        ),
        TrialOutcome::Engaged { plan, note } => CheckResult::warn(
            NAME,
            "engaged, but denial not verified",
            format!("{}: {note}", plan.describe()),
        ),
        TrialOutcome::NotEnforcing { plan } => CheckResult::fail(
            NAME,
            "the sandboxed child read a file outside its scope",
            format!("{} is NOT enforcing on this host", plan.describe()),
        ),
        TrialOutcome::Failed {
            plan: Some(plan),
            error,
        } => CheckResult::fail(
            NAME,
            "sandbox engagement failed — native plugins will not start",
            format!("{}: {error}", plan.describe()),
        ),
        TrialOutcome::Failed { plan: None, error } => {
            CheckResult::warn(NAME, "no sandbox can be engaged here", error)
        }
        TrialOutcome::Skipped { reason } => CheckResult::skip(NAME, reason),
    }
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

/// Clock-skew check: ask the daemon for its wall-clock time, compare to local.
async fn check_clock_skew(daemon_reachable: bool) -> CheckResult {
    if !daemon_reachable {
        return CheckResult::skip("clock-skew", "skipped (daemon not reachable)");
    }
    let client = entangle_rpc::Client::new(entangle_rpc::Client::default_socket());
    let daemon_ms = match client.time().await {
        Ok(t) => t.unix_millis,
        Err(e) => {
            return CheckResult::warn(
                "clock-skew",
                "time() RPC failed",
                format!("could not read daemon clock: {e}"),
            );
        }
    };
    let local_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let skew_ms = local_ms.abs_diff(daemon_ms);
    if skew_ms <= 2_000 {
        CheckResult::ok("clock-skew", format!("OK — within {skew_ms}ms"))
    } else if skew_ms <= 30_000 {
        CheckResult::warn(
            "clock-skew",
            format!("{skew_ms}ms drift between CLI and daemon"),
            "consider running NTP; biscuit-auth tokens have ±60s allowance",
        )
    } else {
        CheckResult::fail(
            "clock-skew",
            format!("severe drift: {skew_ms}ms"),
            "biscuit-auth and pairing TOFU may reject; sync system clock (NTP / chrony)",
        )
    }
}

// ---------------------------------------------------------------------------
// Check 14 — tailscale liveness (only when `[mesh.tailscale] enabled`)
// ---------------------------------------------------------------------------

/// What the daemon will do with `[mesh.tailscale]`, as far as doctor can tell.
enum TailscaleSettings {
    /// Not enabled: nothing to check.
    Off,
    /// `enabled = true` but `[mesh] transports` does not list `"tailscale"`,
    /// so the daemon does not run the transport.
    Inert,
    /// `config.toml` could not be read or parsed (the config row says why).
    Unreadable(String),
    /// A value the daemon rejects at load time.
    Invalid(String),
    /// The daemon runs the transport with this CLI path.
    On { cli: String },
}

/// Read `[mesh.tailscale]` straight from the TOML: the CLI's typed `Config`
/// intentionally does not carry daemon-only sections. Mirrors the daemon's
/// activation rule (`entangle_bin::tailscale::enabled`: `enabled = true`
/// **and** `"tailscale"` in `[mesh] transports`) and its load-time checks.
fn tailscale_settings(raw: Option<&str>) -> TailscaleSettings {
    let Some(raw) = raw else {
        return TailscaleSettings::Off;
    };
    let v: toml::Value = match toml::from_str(raw) {
        Ok(v) => v,
        Err(e) => return TailscaleSettings::Unreadable(format!("config.toml does not parse: {e}")),
    };
    let mesh = v.get("mesh");
    let Some(ts) = mesh.and_then(|m| m.get("tailscale")) else {
        return TailscaleSettings::Off;
    };
    if ts.get("enabled").and_then(toml::Value::as_bool) != Some(true) {
        return TailscaleSettings::Off;
    }
    if let Some(mode) = ts.get("acl-mode") {
        let ok = mode
            .as_str()
            .is_some_and(|m| m.parse::<entangle_mesh_tailscale::AclMode>().is_ok());
        if !ok {
            return TailscaleSettings::Invalid(format!(
                "invalid [mesh.tailscale] acl-mode {mode} (expected \"entangle-on-top\" or \"trust-tailnet\")"
            ));
        }
    }
    if let Some(ip) = ts.get("bind-ip") {
        if ip
            .as_str()
            .and_then(|s| s.parse::<std::net::IpAddr>().ok())
            .is_none()
        {
            return TailscaleSettings::Invalid(format!(
                "invalid [mesh.tailscale] bind-ip {ip} (expected an IP address)"
            ));
        }
    }
    let listed = mesh
        .and_then(|m| m.get("transports"))
        .and_then(toml::Value::as_array)
        .is_some_and(|a| a.iter().any(|t| t.as_str() == Some("tailscale")));
    if !listed {
        return TailscaleSettings::Inert;
    }
    let cli = ts
        .get("tailscale-cli")
        .and_then(toml::Value::as_str)
        .unwrap_or("")
        .to_owned();
    TailscaleSettings::On { cli }
}

async fn check_tailscale() -> CheckResult {
    use entangle_mesh_tailscale::{MeshTailscaleConfig, StatusSource as _, TailnetState};
    let path = config::config_path();
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => Some(raw),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return CheckResult::skip("tailscale", format!("cannot read {}: {e}", path.display()))
        }
    };
    let cli = match tailscale_settings(raw.as_deref()) {
        TailscaleSettings::Off => {
            return CheckResult::skip("tailscale", "mesh.tailscale not enabled")
        }
        TailscaleSettings::Unreadable(why) => {
            return CheckResult::skip("tailscale", format!("{why} (see the config row)"))
        }
        TailscaleSettings::Inert => {
            return CheckResult::warn(
                "tailscale",
                "enabled, but [mesh] transports does not list \"tailscale\"",
                "the daemon does not run the transport; add \"tailscale\" to [mesh] transports or set [mesh.tailscale] enabled = false",
            )
        }
        TailscaleSettings::Invalid(why) => {
            return CheckResult::fail(
                "tailscale",
                why,
                "`entangled` refuses to start with this config.toml",
            )
        }
        TailscaleSettings::On { cli } => cli,
    };
    let cfg = MeshTailscaleConfig {
        tailscale_cli: cli,
        ..MeshTailscaleConfig::default()
    };
    let obs = cfg.status_source().observe().await;
    let peers = obs
        .status
        .as_ref()
        .map(|s| s.online_peers().count())
        .unwrap_or(0);
    match obs.state {
        TailnetState::Active => CheckResult::ok(
            "tailscale",
            format!("active, {peers} online tailnet peer(s) (single poll; the daemon applies hysteresis)"),
        ),
        TailnetState::Stopped { reason } => CheckResult::warn(
            "tailscale",
            format!("stopped ({reason})"),
            "run `tailscale up`; peers reachable only via mesh.tailscale are unreachable meanwhile",
        ),
        TailnetState::Uninstalled => CheckResult::warn(
            "tailscale",
            "uninstalled",
            format!(
                "`{}` not found; install Tailscale or set [mesh.tailscale] enabled = false",
                cfg.resolve_cli()
            ),
        ),
    }
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
    println!("{label}  {:<24}  {combined}", c.name);
}

// ---------------------------------------------------------------------------
// Wrapper check (spec §8.3 item 3)
// ---------------------------------------------------------------------------

/// How long the probe shell may take to start, load its rc files and answer
/// (override: `ENTANGLE_DOCTOR_PROBE_TIMEOUT_MS`).
fn wrapper_probe_timeout() -> std::time::Duration {
    std::env::var("ENTANGLE_DOCTOR_PROBE_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(std::time::Duration::from_millis)
        .unwrap_or(std::time::Duration::from_secs(8))
}

/// Is the shell shim in place and not shadowed?
///
/// Opt-in: skipped unless `[wrappers] install = true`. Block missing/damaged
/// is a warning naming `entangle wrapper enable|repair`; shadowing (the
/// user's own shell resolves the name to an alias, another function or a
/// file) is a failure, so `entangle doctor` exits 1 (ATC-WRP-3).
async fn check_wrappers() -> CheckResult {
    use super::rcblock;
    use super::wrapper::{self, Resolution};

    const NAME: &str = "wrapper";
    if !wrapper::wrappers_enabled() {
        return CheckResult::skip(
            NAME,
            "not enabled (opt-in); `entangle wrapper enable` installs the warning shim",
        );
    }
    let hosts = rcblock::hosts_from_adapters();
    let rcs = match wrapper::rc_files() {
        Ok(r) => r,
        Err(e) => return CheckResult::warn(NAME, "cannot locate rc files", format!("{e:#}")),
    };
    let mut problems: Vec<String> = Vec::new();
    let mut missing: Vec<&str> = Vec::new();
    let mut statuses = Vec::new();
    for rc in &rcs {
        match wrapper::rc_status(rc, &hosts) {
            Ok(st) => {
                match &st {
                    wrapper::RcStatus::Missing | wrapper::RcStatus::Absent => {
                        missing.push(rc.label)
                    }
                    wrapper::RcStatus::Duplicated(_) | wrapper::RcStatus::Damaged(_) => {
                        problems.push(format!("{}: {}", rc.label, st.describe()));
                    }
                    wrapper::RcStatus::Outdated => {
                        problems.push(format!("{}: {}", rc.label, st.describe()));
                    }
                    wrapper::RcStatus::Installed => {}
                }
                statuses.push((rc, st));
            }
            Err(e) => problems.push(format!("{e:#}")),
        }
    }
    if !missing.is_empty() {
        problems.push(format!(
            "wrapper block missing from {}; run `entangle wrapper enable`",
            missing.join(", ")
        ));
    }

    // Shadowing: ask the user's own shell how it resolves each name.
    let mut shadows: Vec<String> = Vec::new();
    let mut note = String::new();
    let shell_path = std::env::var_os("SHELL").map(std::path::PathBuf::from);
    let kind = shell_path
        .as_ref()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let has_block = |shell: &str| {
        statuses
            .iter()
            .any(|(rc, st)| rc.shell == shell && st.has_block())
    };
    if kind == "bash" || kind == "zsh" {
        if has_block(&kind) {
            let bins: Vec<String> = hosts.iter().map(|h| h.binary.clone()).collect();
            let sp = shell_path.clone().unwrap_or_default();
            match wrapper::probe_shell(&sp, &bins, wrapper_probe_timeout()).await {
                Ok(res) => {
                    // A name the shell never answered for was not checked:
                    // the rc file exec'd or exited before the probe script
                    // ran (`exec tmux`, `exec zsh`). That is "could not
                    // check", never a pass.
                    let unanswered: Vec<&str> = bins
                        .iter()
                        .filter(|b| !res.iter().any(|(r, _)| r == *b))
                        .map(String::as_str)
                        .collect();
                    if !unanswered.is_empty() {
                        problems.push(format!(
                            "shadow check could not run for {}: the {kind} shell exited before \
                             answering (does an rc file `exec` or `exit` in interactive shells?)",
                            unanswered.join(", ")
                        ));
                    }
                    for (bin, r) in res {
                        let advice = format!("Run 'entangle wrapper repair' or 'unalias {bin}'.");
                        match r {
                            Resolution::Wrapper => {}
                            Resolution::File(p) => shadows.push(format!(
                                "'{bin}' is shadowed by {p} (PATH ahead of shell function). {advice}"
                            )),
                            Resolution::Alias(a) => shadows.push(format!(
                                "'{bin}' is shadowed by alias '{a}'. {advice}"
                            )),
                            Resolution::OtherFunction { from } => shadows.push(format!(
                                "'{bin}' is shadowed by a different shell function{}. {advice}",
                                from.map(|f| format!(" defined in {f}")).unwrap_or_default()
                            )),
                            Resolution::NotFound => problems.push(format!(
                                "'{bin}' is neither a function nor on PATH in a new {kind} shell \
                                 (is the wrapper block sourced by interactive shells?)"
                            )),
                            Resolution::Other(l) => {
                                problems.push(format!("'{bin}' resolves unexpectedly: {l}"));
                            }
                        }
                    }
                }
                Err(e) => problems.push(format!(
                    "shadow check could not run ({e:#}); the shell was not probed"
                )),
            }
        } else {
            note = format!("shadow check skipped: no wrapper block in {kind}'s rc file");
        }
    } else {
        note = format!(
            "shadow check skipped: $SHELL is {}; only bash and zsh are probed",
            if kind.is_empty() {
                "unset".to_owned()
            } else {
                kind.clone()
            }
        );
    }

    if !shadows.is_empty() {
        let mut all = shadows;
        all.extend(problems);
        return CheckResult::fail(NAME, "shadowed", all.join("; "));
    }
    if !problems.is_empty() {
        return CheckResult::warn(NAME, "needs attention", problems.join("; "));
    }
    let ok = format!(
        "shim installed for {}{}",
        hosts
            .iter()
            .map(|h| h.binary.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        if note.is_empty() {
            String::new()
        } else {
            format!(" ({note})")
        }
    );
    CheckResult::ok(NAME, ok)
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run() -> anyhow::Result<()> {
    let color = std::io::stdout().is_terminal();
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

    let policy = sandbox_policy();
    results.push(check_os_sandbox(policy));
    results.push(check_sandbox_trial(policy));
    results.push(check_disk_space());
    results.push(check_clock_skew(daemon_reachable).await);
    results.push(check_tailscale().await);
    results.push(check_wrappers().await);

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

    println!();
    let skip_str = if n_skip > 0 {
        format!(", {n_skip} skip")
    } else {
        String::new()
    };
    println!("Summary: {n_ok} ok, {n_warn} warn, {n_fail} fail{skip_str}");

    if any_fail {
        std::process::exit(1);
    }
    Ok(())
}
