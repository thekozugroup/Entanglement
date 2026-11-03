//! `entangle agent {run,list}` — launch an AI coding agent behind the MCP
//! gateway (spec §8.3).

use anyhow::{anyhow, bail, Context, Result};
use camino::Utf8PathBuf;
use clap::{Args, Subcommand};
use entangle_agent_host::{
    find_adapter, generate_bearer_token, known_adapter_names, registry, AgentSession, Gateway,
    GatewayConfig, McpServerSpec, Policy,
};
use std::path::PathBuf;
use std::time::Duration;

/// Environment variable carrying the bearer token to the agent.
const TOKEN_ENV: &str = "ENTANGLE_SESSION_TOKEN";

#[derive(Args)]
pub struct AgentArgs {
    #[command(subcommand)]
    cmd: AgentCmd,
}

#[derive(Subcommand)]
enum AgentCmd {
    /// Run an agent with every MCP server routed through a per-session gateway.
    #[command(long_about = "\
Run an AI coding agent with every MCP server routed through a per-session,
loopback-only, bearer-authenticated gateway that enforces tool policy and
records an audit trail.

Your own agent config is read but never modified: a rewritten copy is written
to a session directory (removed on exit) and the agent is launched against it.
Arguments after `--` are passed to the agent unchanged.

Example:
  entangle agent run claude-code --deny 'fs/delete_file' -- --model opus")]
    Run(RunArgs),
    /// List the supported agents and where their MCP config lives.
    List,
}

#[derive(Args)]
struct RunArgs {
    /// Agent to run (see `entangle agent list`).
    agent: String,
    /// Read the agent's MCP config from this file instead of its default location.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Launch this executable instead of the agent's default binary.
    #[arg(long, value_name = "PATH")]
    bin: Option<PathBuf>,
    /// Allow only these `server/tool` patterns (`server/*` and `*` allowed). Repeatable.
    #[arg(long, value_name = "PATTERN")]
    allow: Vec<String>,
    /// Deny these `server/tool` patterns (wins over --allow). Repeatable.
    #[arg(long, value_name = "PATTERN")]
    deny: Vec<String>,
    /// Arguments passed to the agent.
    #[arg(last = true)]
    agent_args: Vec<String>,
}

pub async fn run(a: AgentArgs) -> Result<i32> {
    match a.cmd {
        AgentCmd::List => {
            list();
            Ok(0)
        }
        AgentCmd::Run(r) => run_agent(r).await,
    }
}

fn list() {
    println!("{:<12} {:<10} CONFIG", "AGENT", "BINARY");
    for ad in registry() {
        let cfg = ad
            .config_path()
            .map_or_else(|_| "-".to_string(), |p| p.to_string());
        println!("{:<12} {:<10} {}", ad.name(), ad.binary(), cfg);
    }
}

/// Directory holding per-session directories.
fn sessions_root() -> PathBuf {
    if let Some(d) = std::env::var_os("ENTANGLE_SESSIONS_DIR") {
        return PathBuf::from(d);
    }
    if let Some(d) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(d).join("entangle").join("sessions");
    }
    crate::config::entangle_dir().join("sessions")
}

fn new_session_id() -> String {
    use rand_core::{OsRng, RngCore};
    let mut b = [0u8; 8];
    OsRng.fill_bytes(&mut b);
    format!("sess-{}", hex::encode(b))
}

fn utf8(p: PathBuf) -> Result<Utf8PathBuf> {
    Utf8PathBuf::from_path_buf(p).map_err(|p| anyhow!("path is not valid UTF-8: {}", p.display()))
}

#[cfg(unix)]
fn exit_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}

#[cfg(not(unix))]
fn exit_code(status: std::process::ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

/// Resolve when the user asks us to stop (Ctrl-C / SIGTERM). Returns whether
/// the child already received the signal from the terminal (SIGINT).
async fn stop_requested() -> bool {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => return true,
                _ = term.recv() => return false,
            }
        }
    }
    let _ = tokio::signal::ctrl_c().await;
    true
}

async fn run_agent(args: RunArgs) -> Result<i32> {
    if find_adapter(&args.agent).is_none() {
        bail!(
            "unknown agent '{}'. Known agents: {}",
            args.agent,
            known_adapter_names()
        );
    }
    let source = args.config.clone().map(utf8).transpose()?;
    let mut session = AgentSession::prepare(&args.agent, source.as_deref())
        .with_context(|| format!("reading {} MCP config", args.agent))?;

    for (name, file) in session.unmediated_servers() {
        eprintln!(
            "warning: MCP server '{name}' is declared in {file}, not in {source}; it is \
             disabled in this session because the gateway only runs the servers of {source} \
             (use --config {file} to run that file's servers through the gateway)",
            source = session.source_path(),
        );
    }
    let servers = session.servers().clone();
    for (name, spec) in &servers {
        if let McpServerSpec::Http { url } = spec {
            eprintln!(
                "warning: MCP server '{name}' is remote HTTP ({url}); the gateway does not proxy \
                 HTTP servers, so it will be unavailable in this session"
            );
        }
    }

    let token = generate_bearer_token();
    let gateway = Gateway::new(GatewayConfig {
        bearer_token: token.clone(),
        ..GatewayConfig::default()
    })
    .with_servers(servers)
    .with_policy(Policy {
        allow: args.allow.clone(),
        deny: args.deny.clone(),
    })
    .with_request_timeout(Duration::from_secs(120));
    let handle = gateway.start().await.context("starting MCP gateway")?;

    let session_id = new_session_id();
    let outcome = launch(&mut session, &args, &session_id, &token, &handle.base_url()).await;

    let audit = handle.audit_log();
    handle.shutdown().await;
    let cleanup = session.cleanup();
    let denied = audit
        .iter()
        .filter(|r| r.decision == entangle_agent_host::AuditDecision::Deny)
        .count();
    tracing::info!(session = %session_id, tool_calls = audit.len(), denied, "agent session ended");

    let code = outcome?;
    if let Err(e) = cleanup {
        // The agent ran and its exit status is still the primary result, but
        // a modified original config is something the operator must see.
        eprintln!("warning: {e}");
    }
    Ok(code)
}

async fn launch(
    session: &mut AgentSession,
    args: &RunArgs,
    session_id: &str,
    token: &str,
    base_url: &str,
) -> Result<i32> {
    // `activate` creates the directory (mode 0700, missing parents too) and
    // owns it: it is removed if activation fails and by `cleanup` otherwise.
    let dir = utf8(sessions_root().join(session_id))?;
    let plan = session
        .activate(&dir, base_url, TOKEN_ENV)
        .context("writing session config")?
        .clone();

    let bin = args
        .bin
        .clone()
        .unwrap_or_else(|| PathBuf::from(session.binary()));
    let mut cmd = tokio::process::Command::new(&bin);
    cmd.args(&plan.args)
        .args(&args.agent_args)
        .env("ENTANGLE_SESSION_ID", session_id)
        .env(TOKEN_ENV, token)
        .kill_on_drop(true);
    for (k, v) in &plan.env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().with_context(|| {
        format!(
            "launching '{}' (is it installed and on PATH? use --bin to point at it)",
            bin.display()
        )
    })?;

    tokio::select! {
        status = child.wait() => Ok(exit_code(status.context("waiting for agent")?)),
        child_got_it = stop_requested() => {
            if child_got_it {
                // The terminal delivered SIGINT to the agent as well; give it
                // a grace period to exit on its own.
                if let Ok(status) = tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
                    return Ok(exit_code(status.context("waiting for agent")?));
                }
            }
            let _ = child.kill().await;
            Ok(130)
        }
    }
}
