//! Consent on change for the user-level MCP servers of an agent session
//! (spec §8.3, §11).
//!
//! The sandboxed agent may write its own config (`~/.claude.json`,
//! `~/.codex/config.toml`): that is where it keeps its state. A stdio server
//! it adds there would be started by the gateway of the *next* session,
//! outside the sandbox. So the set of user-level servers the user has seen
//! is recorded, as one digest per server, in
//! `~/.entangle/agent-host/approved-servers.json` (outside the agent's
//! allowlist), and a server that is new or changed since the record needs
//! the same consent as a project's servers: `--trust-new-servers`, or a `y`
//! at a terminal prompt. The first session of an agent and config file
//! records the existing set after listing it once.

use anyhow::{bail, Context, Result};
use entangle_agent_host::McpServerSpec;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Approved servers: `"<agent> <config path>"` → server name → digest.
type Record = BTreeMap<String, BTreeMap<String, String>>;

/// Where the record lives.
pub(crate) fn record_path() -> PathBuf {
    crate::config::entangle_dir()
        .join("agent-host")
        .join("approved-servers.json")
}

/// The digest of one server's definition: what it runs or contacts. Env
/// values are included (an injected `NODE_OPTIONS` changes what runs);
/// header values are not (they are credentials expanded from the
/// environment and may rotate), only their names. Only the digest is
/// stored, never a value.
pub(crate) fn digest(spec: &McpServerSpec) -> String {
    use sha2::Digest as _;
    let canonical = match spec {
        McpServerSpec::Stdio { command, args, env } => serde_json::json!({
            "kind": "stdio", "command": command, "args": args, "env": env,
        }),
        McpServerSpec::Http { url, headers } => serde_json::json!({
            "kind": "http", "url": url, "headers": headers.keys().collect::<Vec<_>>(),
        }),
        McpServerSpec::LegacySse { url } => serde_json::json!({ "kind": "sse", "url": url }),
    };
    hex::encode(sha2::Sha256::digest(canonical.to_string().as_bytes()))
}

/// The servers of `servers` that are new or changed relative to `approved`.
pub(crate) fn new_or_changed<'a>(
    servers: &'a BTreeMap<String, McpServerSpec>,
    approved: &BTreeMap<String, String>,
) -> Vec<(&'a str, &'a McpServerSpec)> {
    servers
        .iter()
        .filter(|(name, spec)| approved.get(*name) != Some(&digest(spec)))
        .map(|(n, s)| (n.as_str(), s))
        .collect()
}

fn load(path: &Path) -> Result<Record> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("reading the approved MCP servers in {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Record::new()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

fn save(path: &Path, record: &Record) -> Result<()> {
    let dir = path.parent().context("record path has no parent")?;
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    let tmp = dir.join(format!(".approved-servers.{}.tmp", std::process::id()));
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o
            .open(&tmp)
            .with_context(|| format!("writing {}", tmp.display()))?;
        std::io::Write::write_all(&mut f, serde_json::to_string_pretty(record)?.as_bytes())?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))
}

fn show(name: &str, spec: &McpServerSpec) {
    match spec {
        McpServerSpec::Stdio { command, args, env } => {
            let env_names: Vec<&String> = env.keys().collect();
            eprintln!("  {name:?}: command {command:?}, args {args:?}, env vars {env_names:?}");
        }
        McpServerSpec::Http { url, headers } => {
            let shown = entangle_agent_host::gateway::display_url(url);
            let names: Vec<&String> = headers.keys().collect();
            eprintln!("  {name:?}: url {shown:?}, headers {names:?}");
        }
        McpServerSpec::LegacySse { url } => {
            let shown = entangle_agent_host::gateway::display_url(url);
            eprintln!("  {name:?}: legacy SSE url {shown:?} (refused by the gateway)");
        }
    }
}

/// Check the user-level servers of `config` for `agent` against the record
/// at `record_file` and ask for consent where needed (see the module docs).
/// `trusted` is `--trust-new-servers`; `interactive` says whether stdin is a
/// terminal to prompt on. On consent (or on the first session) the current
/// set is recorded.
pub(crate) fn confirm_user_servers(
    record_file: &Path,
    agent: &str,
    config: &str,
    servers: &BTreeMap<String, McpServerSpec>,
    trusted: bool,
    interactive: bool,
) -> Result<()> {
    let mut record = load(record_file)?;
    let key = format!("{agent} {config}");
    let current: BTreeMap<String, String> = servers
        .iter()
        .map(|(n, s)| (n.clone(), digest(s)))
        .collect();
    match record.get(&key) {
        None => {
            if !servers.is_empty() {
                eprintln!(
                    "First session of {agent} with {config}: these user-level MCP server(s) are \
                     recorded as approved; a server added or changed later will need your \
                     consent:"
                );
                // Names and what they run, briefly: the full definition
                // (arguments included) is listed when one changes.
                for (name, spec) in servers {
                    match spec {
                        McpServerSpec::Stdio { command, .. } => {
                            eprintln!("  {name:?}: command {command:?}");
                        }
                        McpServerSpec::Http { url, .. } | McpServerSpec::LegacySse { url } => {
                            let shown = entangle_agent_host::gateway::display_url(url);
                            eprintln!("  {name:?}: url {shown:?}");
                        }
                    }
                }
            }
        }
        Some(approved) => {
            let changed = new_or_changed(servers, approved);
            if changed.is_empty() {
                if approved.len() != current.len() {
                    // Only removals: record the smaller set.
                    record.insert(key, current);
                    save_or_warn(record_file, &record);
                }
                return Ok(());
            }
            eprintln!(
                "{config} declares {} MCP server(s) that are new or changed since you last \
                 approved its servers (the agent itself may have written them; the gateway would \
                 start or contact them outside the sandbox):",
                changed.len()
            );
            for (name, spec) in &changed {
                show(name, spec);
            }
            if !trusted {
                if !interactive {
                    bail!(
                        "ENTANGLE-E0684: refusing to start new or changed MCP servers of {config} \
                         without consent: re-run with --trust-new-servers, or run in a terminal \
                         and answer the prompt"
                    );
                }
                eprint!("Start these servers? [y/N] ");
                let mut answer = String::new();
                std::io::stdin()
                    .read_line(&mut answer)
                    .context("reading the answer")?;
                if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                    bail!(
                        "ENTANGLE-E0684: not starting the new or changed MCP servers of \
                         {config}: declined"
                    );
                }
            }
        }
    }
    record.insert(key, current);
    save_or_warn(record_file, &record);
    Ok(())
}

fn save_or_warn(path: &Path, record: &Record) {
    if let Err(e) = save(path, record) {
        eprintln!("warning: the approved MCP servers could not be recorded: {e:#}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stdio(cmd: &str) -> McpServerSpec {
        McpServerSpec::Stdio {
            command: cmd.into(),
            args: vec!["-y".into()],
            env: BTreeMap::new(),
        }
    }

    #[test]
    fn first_session_records_then_unchanged_set_passes_and_a_new_server_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let rec = dir.path().join("agent-host/approved-servers.json");
        let mut servers = BTreeMap::from([("fs".to_owned(), stdio("npx"))]);
        // First session: recorded without a prompt.
        confirm_user_servers(
            &rec,
            "claude-code",
            "/h/.claude.json",
            &servers,
            false,
            false,
        )
        .unwrap();
        assert!(rec.exists());
        // Unchanged: no consent needed.
        confirm_user_servers(
            &rec,
            "claude-code",
            "/h/.claude.json",
            &servers,
            false,
            false,
        )
        .unwrap();
        // Added between sessions: refused without consent.
        servers.insert("evil".into(), stdio("/tmp/payload"));
        let err = confirm_user_servers(
            &rec,
            "claude-code",
            "/h/.claude.json",
            &servers,
            false,
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("ENTANGLE-E0684"), "{err}");
        assert!(err.to_string().contains("--trust-new-servers"), "{err}");
        // Still refused next time: a refusal records nothing.
        assert!(confirm_user_servers(
            &rec,
            "claude-code",
            "/h/.claude.json",
            &servers,
            false,
            false
        )
        .is_err());
        // --trust-new-servers approves and records it.
        confirm_user_servers(
            &rec,
            "claude-code",
            "/h/.claude.json",
            &servers,
            true,
            false,
        )
        .unwrap();
        confirm_user_servers(
            &rec,
            "claude-code",
            "/h/.claude.json",
            &servers,
            false,
            false,
        )
        .unwrap();
    }

    #[test]
    fn a_changed_command_args_or_env_counts_as_new() {
        let approved = BTreeMap::from([("fs".to_owned(), digest(&stdio("npx")))]);
        let same = BTreeMap::from([("fs".to_owned(), stdio("npx"))]);
        assert!(new_or_changed(&same, &approved).is_empty());
        let cmd = BTreeMap::from([("fs".to_owned(), stdio("sh"))]);
        assert_eq!(new_or_changed(&cmd, &approved).len(), 1);
        let env = BTreeMap::from([(
            "fs".to_owned(),
            McpServerSpec::Stdio {
                command: "npx".into(),
                args: vec!["-y".into()],
                env: BTreeMap::from([("NODE_OPTIONS".into(), "--require /tmp/x".into())]),
            },
        )]);
        assert_eq!(new_or_changed(&env, &approved).len(), 1);
        let url = |u: &str| McpServerSpec::Http {
            url: u.into(),
            headers: BTreeMap::new(),
        };
        assert_ne!(digest(&url("https://a")), digest(&url("https://b")));
    }

    #[test]
    fn records_are_per_agent_and_config() {
        let dir = tempfile::tempdir().unwrap();
        let rec = dir.path().join("approved-servers.json");
        let empty = BTreeMap::new();
        confirm_user_servers(&rec, "codex", "/h/.codex/config.toml", &empty, false, false).unwrap();
        let one = BTreeMap::from([("x".to_owned(), stdio("x"))]);
        // Another agent's first session records without asking ...
        confirm_user_servers(&rec, "claude-code", "/h/.claude.json", &one, false, false).unwrap();
        // ... but a server appearing in a recorded (empty) set needs consent.
        assert!(
            confirm_user_servers(&rec, "codex", "/h/.codex/config.toml", &one, false, false)
                .is_err()
        );
    }
}
