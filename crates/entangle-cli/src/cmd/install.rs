//! `entangle install`, `entangle uninstall` and `entangle agent host cleanup`
//! (spec §8.3 "Cleanup-on-uninstall" and wrapper item 2, §9.2).
//!
//! * **install** is the first-run path: `entangle init` when this device has
//!   no identity yet, the wrapper question (`--wrapper` / `--no-wrapper`; a
//!   choice already recorded in `[wrappers] install` is respected), and a
//!   SHA-256 checksum of every agent config file Entanglement will never
//!   modify (the user's own claude-code, codex and opencode configs, from the
//!   adapter registry), kept in `~/.entangle/agent-host/install-checksums.json`.
//! * **agent host cleanup** removes per-session agent config directories left
//!   behind (a session killed with SIGKILL cannot remove its own); `--all`
//!   removes every one, in use or not. It only ever deletes `sess-*`
//!   directories under the sessions root, never a user config.
//! * **uninstall** removes the wrapper shims (`entangle wrapper disable`),
//!   runs `agent host cleanup --all`, and checks the recorded checksums,
//!   reporting every agent config that changed since install. Identity, peers
//!   and data stay unless `--purge`, which asks the operator to type `purge`
//!   (or takes `--yes`) and refuses while the daemon is running.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _, Result};
use clap::Args;
use serde::{Deserialize, Serialize};

use crate::cmd::ui::{Prompter, Style};
use crate::config;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// `entangle install` arguments.
#[derive(Args, Debug)]
pub struct InstallArgs {
    /// Install the shell wrappers without asking.
    #[arg(long, conflicts_with = "no_wrapper")]
    pub wrapper: bool,
    /// Do not install the shell wrappers (records the opt-out if none was recorded).
    #[arg(long)]
    pub no_wrapper: bool,
    /// Ask nothing: `entangle init --headless` when there is no identity, and
    /// no wrappers unless --wrapper.
    #[arg(long, alias = "non-interactive")]
    pub headless: bool,
}

/// `entangle uninstall` arguments.
#[derive(Args, Debug)]
pub struct UninstallArgs {
    /// Also delete ~/.entangle: the identity key, paired peers, keyrings,
    /// config and plugin data. Asks you to type `purge` unless --yes.
    #[arg(long)]
    pub purge: bool,
    /// Confirm --purge without asking.
    #[arg(long, short = 'y', requires = "purge")]
    pub yes: bool,
}

// ---------------------------------------------------------------------------
// Agent config checksums
// ---------------------------------------------------------------------------

/// One agent config file as it was at install.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recorded {
    /// Agent name (`claude-code`, ...).
    pub agent: String,
    /// Absolute path.
    pub path: String,
    /// Hex SHA-256 of the contents; `None` when the file did not exist.
    pub sha256: Option<String>,
}

/// The checksum record.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChecksumRecord {
    /// Unix seconds of the first install that recorded them.
    pub recorded_unix: u64,
    /// The files.
    pub files: Vec<Recorded>,
}

/// Where the record lives.
pub fn checksums_path() -> PathBuf {
    config::entangle_dir()
        .join("agent-host")
        .join("install-checksums.json")
}

fn sha256_of(path: &Path) -> Result<Option<String>> {
    use sha2::Digest as _;
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(hex::encode(sha2::Sha256::digest(&bytes)))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// The user's own agent config files, from the adapter registry.
pub fn agent_config_files() -> Vec<(String, PathBuf)> {
    entangle_agent_host::registry()
        .iter()
        .flat_map(|a| {
            let name = a.name().to_owned();
            a.user_config_files()
                .into_iter()
                .map(move |p| (name.clone(), p.into_std_path_buf()))
        })
        .collect()
}

/// Record the checksums of `files`, keeping what an earlier install
/// recorded (the baseline is the first install).
fn record_checksums(files: &[(String, PathBuf)]) -> Result<ChecksumRecord> {
    let path = checksums_path();
    let mut rec = load_checksums()?.unwrap_or_else(|| ChecksumRecord {
        recorded_unix: crate::cmd::pairlog::now(),
        files: Vec::new(),
    });
    for (agent, file) in files {
        let shown = file.display().to_string();
        if rec.files.iter().any(|r| r.path == shown) {
            continue;
        }
        rec.files.push(Recorded {
            agent: agent.clone(),
            path: shown,
            sha256: sha256_of(file)?,
        });
    }
    let bytes = serde_json::to_vec_pretty(&rec)?;
    crate::fsutil::atomic_write(&path, &bytes, 0o600)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(rec)
}

fn load_checksums() -> Result<Option<ChecksumRecord>> {
    let path = checksums_path();
    match std::fs::read(&path) {
        Ok(b) => Ok(Some(serde_json::from_slice(&b).with_context(|| {
            format!(
                "ENTANGLE-E0792: {} is not a checksum record",
                path.display()
            )
        })?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// How a recorded file compares now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Same bytes (or still absent).
    Unchanged,
    /// Different bytes.
    Changed,
    /// Existed at install, gone now.
    Removed,
    /// Absent at install, present now.
    Created,
}

/// Compare every recorded file with what is on disk now.
pub fn verify(rec: &ChecksumRecord) -> Result<Vec<(Recorded, Verdict)>> {
    rec.files
        .iter()
        .map(|r| {
            let now = sha256_of(Path::new(&r.path))?;
            let v = match (&r.sha256, &now) {
                (a, b) if a == b => Verdict::Unchanged,
                (Some(_), None) => Verdict::Removed,
                (None, Some(_)) => Verdict::Created,
                _ => Verdict::Changed,
            };
            Ok((r.clone(), v))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Session directories
// ---------------------------------------------------------------------------

/// The marker `entangle agent run` writes into its session directory.
pub const SESSION_OWNER: &str = ".entangle-session.json";

/// Who owns a session directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionOwner {
    /// The `entangle agent run` process.
    pub pid: u32,
    /// Agent name.
    pub agent: String,
    /// Unix seconds when it started.
    pub started_unix: u64,
}

/// Record this process as the owner of `dir` (called by `entangle agent
/// run` right after the session directory is created).
pub fn write_session_owner(dir: &Path, agent: &str) -> Result<()> {
    let owner = SessionOwner {
        pid: std::process::id(),
        agent: agent.to_owned(),
        started_unix: crate::cmd::pairlog::now(),
    };
    crate::fsutil::atomic_write(
        &dir.join(SESSION_OWNER),
        &serde_json::to_vec(&owner)?,
        0o600,
    )
    .with_context(|| format!("writing the session owner into {}", dir.display()))
}

/// Whether process `pid` exists (owned by anyone).
fn pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Ok(raw) = i32::try_from(pid) else {
            return false;
        };
        match rustix::process::Pid::from_raw(raw) {
            // `kill(pid, 0)`: Ok = alive; EPERM = alive, another user's.
            Some(p) => !matches!(
                rustix::process::test_kill_process(p),
                Err(rustix::io::Errno::SRCH)
            ),
            None => false,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

/// A session directory older than this with no owner record is stale.
const UNOWNED_STALE_SECS: u64 = 24 * 3600;

/// What cleanup decided for one directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SessionOutcome {
    /// The directory.
    pub path: String,
    /// `removed` or `kept`.
    pub action: &'static str,
    /// Why.
    pub reason: String,
}

fn is_session_name(name: &str) -> bool {
    name.strip_prefix("sess-")
        .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Remove stale session directories under `root` (or every one with
/// `all`). Only directories named `sess-<hex>` directly under `root` are
/// considered, never through a symbolic link.
pub fn cleanup_sessions(root: &Path, all: bool) -> Result<Vec<SessionOutcome>> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(root) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e).with_context(|| format!("reading {}", root.display())),
    };
    let now = std::time::SystemTime::now();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        // An entry that disappears meanwhile (a session ending) is skipped.
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !is_session_name(&name) || !meta.file_type().is_dir() {
            continue;
        }
        let owner: Option<SessionOwner> = std::fs::read(path.join(SESSION_OWNER))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok());
        let age = meta
            .modified()
            .ok()
            .and_then(|m| now.duration_since(m).ok())
            .map_or(0, |d| d.as_secs());
        let (stale, why) = match &owner {
            Some(o) if pid_alive(o.pid) => (
                false,
                format!(
                    "in use by `entangle agent run` (pid {}, {})",
                    o.pid, o.agent
                ),
            ),
            Some(o) => (
                true,
                format!(
                    "its `entangle agent run` (pid {}, {}) is gone",
                    o.pid, o.agent
                ),
            ),
            None if age >= UNOWNED_STALE_SECS => {
                (true, format!("no owner record, {}h old", age / 3600))
            }
            None => (false, "no owner record and less than a day old".to_owned()),
        };
        if stale || all {
            std::fs::remove_dir_all(&path)
                .with_context(|| format!("removing {}", path.display()))?;
            out.push(SessionOutcome {
                path: path.display().to_string(),
                action: "removed",
                reason: if stale { why } else { format!("--all ({why})") },
            });
        } else {
            out.push(SessionOutcome {
                path: path.display().to_string(),
                action: "kept",
                reason: why,
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

/// `entangle agent host cleanup [--all]`.
pub fn run_cleanup(all: bool, json: bool) -> Result<()> {
    let root = crate::cmd::agent::sessions_root();
    let outcomes = cleanup_sessions(&root, all)?;
    if json {
        println!(
            "{}",
            serde_json::json!({ "sessions_root": root, "sessions": outcomes })
        );
        return Ok(());
    }
    print_cleanup(&root, &outcomes);
    Ok(())
}

fn print_cleanup(root: &Path, outcomes: &[SessionOutcome]) {
    if outcomes.is_empty() {
        println!("No agent session directories under {}.", root.display());
        return;
    }
    for o in outcomes {
        println!("{:<8} {}  ({})", o.action, o.path, o.reason);
    }
    let removed = outcomes.iter().filter(|o| o.action == "removed").count();
    println!(
        "{removed} session director{} removed under {}; your own agent configs were not touched.",
        if removed == 1 { "y" } else { "ies" },
        root.display()
    );
}

// ---------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------

/// `entangle install`.
pub async fn run_install(a: InstallArgs) -> Result<i32> {
    let st = Style::stdout();
    println!("{}", st.bold("[1/3] Identity and configuration"));
    let init = crate::cmd::init::InitArgs {
        headless: a.headless,
        ..crate::cmd::init::InitArgs::default()
    };
    if let Err(e) = crate::cmd::init::ensure_initialised(init, false).await {
        if let Some(f) = e.downcast_ref::<crate::cmd::init::InitFailure>() {
            eprintln!("{} {}", Style::stderr().error(), f.message);
            return Ok(f.code);
        }
        return Err(e);
    }

    println!("\n{}", st.bold("[2/3] Shell wrappers"));
    match (
        crate::cmd::wrapper::recorded_choice(),
        a.wrapper,
        a.no_wrapper,
    ) {
        (_, true, _) => crate::cmd::wrapper::enable()?,
        (Some(true), _, _) => {
            println!("You opted in earlier ([wrappers] install = true); refreshing the shim.");
            crate::cmd::wrapper::enable()?;
        }
        (Some(false), _, _) => println!(
            "Wrappers stay off: you opted out ([wrappers] install = false). `entangle wrapper \
             enable` turns them on."
        ),
        (None, _, true) => {
            crate::cmd::wrapper::record_opt_out()?;
            println!(
                "Not installing wrappers (--no-wrapper; recorded [wrappers] install = false). \
                 `entangle wrapper enable` turns them on."
            );
        }
        (None, _, false) if a.headless => println!(
            "Skipped (--headless): pass --wrapper to install them, or run `entangle wrapper \
             enable` later."
        ),
        (None, _, false) => {
            if Prompter::new().confirm(
                "Install shell wrappers that warn when agent hosts run outside Entanglement?",
                true,
            )? {
                crate::cmd::wrapper::enable()?;
            } else {
                crate::cmd::wrapper::record_opt_out()?;
                println!(
                    "Not installed (recorded [wrappers] install = false). `entangle wrapper \
                     enable` turns them on."
                );
            }
        }
    }

    println!("\n{}", st.bold("[3/3] Agent configs (never modified)"));
    let rec = record_checksums(&agent_config_files())?;
    for r in &rec.files {
        let state = if r.sha256.is_some() {
            "sha256 recorded"
        } else {
            "absent (recorded)"
        };
        println!("  {:<12} {}  {state}", r.agent, r.path);
    }
    println!(
        "Checksums in {}; `entangle uninstall` verifies these files are unchanged.",
        checksums_path().display()
    );
    println!("\nNext: `entangled run` to start the daemon, `entangle doctor` to check this host.");
    Ok(0)
}

// ---------------------------------------------------------------------------
// uninstall
// ---------------------------------------------------------------------------

/// The directory `--purge` deletes, refusing anything that is not clearly
/// Entanglement's own (`.entangle` or the platform data directory).
fn purge_target() -> Result<PathBuf> {
    let dir = config::entangle_dir();
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let named_ours = dir
        .file_name()
        .is_some_and(|n| n == ".entangle" || n == "entangle");
    if !named_ours || dir.parent().is_none() || home.as_deref() == Some(dir.as_path()) {
        bail!(
            "ENTANGLE-E0790: refusing to purge {}: it does not look like Entanglement's data \
             directory",
            dir.display()
        );
    }
    Ok(dir)
}

/// A daemon answers on the socket (or holds it but is too busy to answer).
/// A missing socket, or a stale one nobody listens on, is not a daemon.
async fn daemon_running() -> bool {
    let client = entangle_rpc::Client::new(entangle_rpc::Client::default_socket());
    matches!(
        client.version().await,
        Ok(_)
            | Err(entangle_rpc::RpcError::ConnectTimeout { .. })
            | Err(entangle_rpc::RpcError::Rpc { .. })
    )
}

/// `entangle uninstall`.
pub async fn run_uninstall(a: UninstallArgs) -> Result<i32> {
    let st = Style::stdout();
    if a.purge && daemon_running().await {
        bail!(
            "ENTANGLE-E0790: the daemon is running; stop it first (e.g. `systemctl stop \
             entangled`), then re-run `entangle uninstall --purge`. Nothing was changed."
        );
    }

    println!("{}", st.bold("[1/4] Shell wrappers"));
    // `wrapper disable` records the opt-out in config.toml; with no
    // ~/.entangle at all, only the rc blocks are removed (uninstall must not
    // create the directory it is cleaning up).
    let removed = if config::entangle_dir().exists() {
        crate::cmd::wrapper::disable()
    } else {
        crate::cmd::wrapper::remove_blocks()
    };
    if let Err(e) = removed {
        eprintln!("{} {e:#}", Style::stderr().warning());
    }

    println!("\n{}", st.bold("[2/4] Agent session directories"));
    let root = crate::cmd::agent::sessions_root();
    let outcomes = cleanup_sessions(&root, true)?;
    print_cleanup(&root, &outcomes);

    println!("\n{}", st.bold("[3/4] Your agent configs"));
    let mut changed = 0;
    match load_checksums()? {
        None => println!(
            "No checksums were recorded (`entangle install` records them); nothing to verify."
        ),
        Some(rec) => {
            for (r, v) in verify(&rec)? {
                let line = match v {
                    Verdict::Unchanged => "unchanged".to_owned(),
                    Verdict::Changed => {
                        changed += 1;
                        format!("{} CHANGED since install", st.warning())
                    }
                    Verdict::Removed => {
                        changed += 1;
                        format!("{} REMOVED since install", st.warning())
                    }
                    Verdict::Created => {
                        changed += 1;
                        format!("{} CREATED since install", st.warning())
                    }
                };
                println!("  {:<12} {}  {line}", r.agent, r.path);
            }
            if changed > 0 {
                println!(
                    "Entanglement never writes these files; if you did not change them \
                     yourself, find out what did."
                );
            }
        }
    }

    println!("\n{}", st.bold("[4/4] Identity and data"));
    let dir = config::entangle_dir();
    if !a.purge {
        println!(
            "Kept {} (identity, paired peers, keyrings, config, plugin data). Delete it with \
             `entangle uninstall --purge`.",
            dir.display()
        );
    } else {
        let target = purge_target()?;
        if !target.exists() {
            println!("{} does not exist; nothing to purge.", target.display());
        } else {
            println!(
                "This deletes {} for good: the identity key (every pairing breaks), paired \
                 peers, keyrings, config and plugin data. Back up first with `entangle backup`.",
                target.display()
            );
            let confirmed = a.yes
                || Prompter::new()
                    .text("Type `purge` to delete it", "")
                    .map(|s| s == "purge")
                    .unwrap_or(false);
            if !confirmed {
                bail!(
                    "ENTANGLE-E0790: purge not confirmed; {} was kept (the wrappers and session \
                     directories above were removed)",
                    target.display()
                );
            }
            std::fs::remove_dir_all(&target)
                .with_context(|| format!("deleting {}", target.display()))?;
            println!("Deleted {}.", target.display());
        }
    }
    println!(
        "\nThe `entangle` and `entangled` binaries (and any service unit) are not removed by \
         this command; see docs/install.md, \"Uninstall\"."
    );
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_session_directories_are_touched() {
        let root = tempfile::tempdir().unwrap();
        let mk = |n: &str| {
            let p = root.path().join(n);
            std::fs::create_dir(&p).unwrap();
            p
        };
        let stale = mk("sess-0123456789abcdef");
        std::fs::write(
            stale.join(SESSION_OWNER),
            serde_json::to_vec(&SessionOwner {
                pid: u32::MAX - 7,
                agent: "codex".into(),
                started_unix: 0,
            })
            .unwrap(),
        )
        .unwrap();
        let live = mk("sess-aaaaaaaaaaaaaaaa");
        write_session_owner(&live, "claude-code").unwrap();
        let fresh_unowned = mk("sess-bbbbbbbbbbbbbbbb");
        let not_ours = mk("my-settings");
        std::fs::write(not_ours.join("settings.json"), "{}").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&not_ours, root.path().join("sess-cccccccccccccccc")).unwrap();

        let out = cleanup_sessions(root.path(), false).unwrap();
        assert!(!stale.exists(), "a dead owner's session is removed");
        assert!(live.exists() && fresh_unowned.exists());
        assert_eq!(out.iter().filter(|o| o.action == "removed").count(), 1);
        assert!(out.iter().any(|o| o.reason.contains("is gone")));

        let out = cleanup_sessions(root.path(), true).unwrap();
        assert!(!live.exists() && !fresh_unowned.exists());
        assert!(out.iter().any(|o| o.reason.contains("--all (in use")));
        // Never anything that is not a session directory, nor through a link.
        assert!(not_ours.join("settings.json").exists());
        assert!(std::fs::symlink_metadata(root.path().join("sess-cccccccccccccccc")).is_ok());
    }

    #[test]
    fn verdicts_cover_every_change() {
        let d = tempfile::tempdir().unwrap();
        let p = |n: &str| d.path().join(n);
        std::fs::write(p("same"), "a").unwrap();
        std::fs::write(p("edit"), "a").unwrap();
        std::fs::write(p("gone"), "a").unwrap();
        let rec = ChecksumRecord {
            recorded_unix: 0,
            files: ["same", "edit", "gone", "new"]
                .iter()
                .map(|n| Recorded {
                    agent: "x".into(),
                    path: p(n).display().to_string(),
                    sha256: sha256_of(&p(n)).unwrap(),
                })
                .collect(),
        };
        std::fs::write(p("edit"), "b").unwrap();
        std::fs::remove_file(p("gone")).unwrap();
        std::fs::write(p("new"), "c").unwrap();
        let v: Vec<Verdict> = verify(&rec).unwrap().into_iter().map(|(_, v)| v).collect();
        assert_eq!(
            v,
            [
                Verdict::Unchanged,
                Verdict::Changed,
                Verdict::Removed,
                Verdict::Created
            ]
        );
    }
}
