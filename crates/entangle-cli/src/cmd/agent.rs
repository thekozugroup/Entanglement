//! `entangle agent {run,list}` — launch an AI coding agent behind the MCP
//! gateway (spec §8.3).

use anyhow::{anyhow, bail, Context, Result};
use camino::Utf8PathBuf;
use clap::{Args, Subcommand};
use entangle_agent_host::{
    find_adapter, generate_bearer_token, known_adapter_names, registry, AgentSession, Gateway,
    GatewayConfig, McpServerSpec, Policy,
};
use std::io::IsTerminal;
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
    /// Start the stdio MCP servers of the project's own config (e.g. the
    /// `.mcp.json` in the current directory) without asking. They are
    /// commands that come with the repository; without this flag they are
    /// listed and need a `y` at a terminal prompt.
    #[arg(long)]
    trust_project_servers: bool,
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

/// How long the agent gets to exit by itself after a stop signal before it
/// is killed.
const STOP_GRACE: Duration = Duration::from_secs(5);

/// A signal asking the session to stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stop {
    /// SIGINT (Ctrl-C).
    Interrupt,
    /// SIGTERM.
    Terminate,
    /// SIGHUP (the terminal was closed).
    Hangup,
}

impl Stop {
    /// Conventional exit status for death by this signal (128 + number).
    fn exit_code(self) -> i32 {
        match self {
            Stop::Interrupt => 130,
            Stop::Terminate => 143,
            Stop::Hangup => 129,
        }
    }
}

/// Take over SIGINT, SIGTERM and SIGHUP (Ctrl-C only, off unix) and publish
/// every one received (the channel holds the most recent). Once installed,
/// these signals no longer kill the CLI outright, so the gateway shutdown and
/// the session cleanup always run.
fn watch_stop_signals() -> Result<tokio::sync::watch::Receiver<Option<Stop>>> {
    let (tx, rx) = tokio::sync::watch::channel(None);
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut int = signal(SignalKind::interrupt()).context("installing a SIGINT handler")?;
        let mut term = signal(SignalKind::terminate()).context("installing a SIGTERM handler")?;
        let mut hup = signal(SignalKind::hangup()).context("installing a SIGHUP handler")?;
        tokio::spawn(async move {
            loop {
                let stop = tokio::select! {
                    _ = int.recv() => Stop::Interrupt,
                    _ = term.recv() => Stop::Terminate,
                    _ = hup.recv() => Stop::Hangup,
                };
                if tx.send(Some(stop)).is_err() {
                    break;
                }
            }
        });
    }
    #[cfg(not(unix))]
    tokio::spawn(async move {
        while tokio::signal::ctrl_c().await.is_ok() {
            if tx.send(Some(Stop::Interrupt)).is_err() {
                break;
            }
        }
    });
    Ok(rx)
}

/// Resolve with the next signal received after this call starts waiting.
///
/// Values already seen are not returned again, so a SIGINT that was handled
/// once cannot make a caller that loops on this function spin. A signal
/// that arrived before the caller first waits (e.g. while the agent was
/// being spawned) is unseen and is returned at once.
async fn next_signal(rx: &mut tokio::sync::watch::Receiver<Option<Stop>>) -> Stop {
    loop {
        if rx.changed().await.is_err() {
            // The signal task is gone; no further signal can arrive.
            std::future::pending::<()>().await;
        }
        if let Some(stop) = *rx.borrow_and_update() {
            return stop;
        }
    }
}

/// Send the agent the signal the CLI received (best effort).
#[cfg(unix)]
fn forward_signal(child: &tokio::process::Child, stop: Stop) {
    use rustix::process::{kill_process, Pid, Signal};
    let sig = match stop {
        Stop::Interrupt => Signal::INT,
        Stop::Terminate => Signal::TERM,
        Stop::Hangup => Signal::HUP,
    };
    // `id()` is `None` once the child has been reaped, so the pid cannot
    // have been reused by another process here.
    if let Some(pid) = child
        .id()
        .and_then(|id| i32::try_from(id).ok())
        .and_then(Pid::from_raw)
    {
        let _ = kill_process(pid, sig);
    }
}

#[cfg(not(unix))]
fn forward_signal(_child: &tokio::process::Child, _stop: Stop) {}

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

    confirm_project_servers(&session, args.trust_project_servers)?;
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

    // From here on, SIGINT/SIGTERM/SIGHUP stop the session through the
    // cleanup below instead of killing the CLI (after the consent prompt,
    // so Ctrl-C at the prompt still simply exits).
    let mut stop = watch_stop_signals()?;

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
    let outcome = launch(
        &mut session,
        &args,
        &session_id,
        &token,
        &handle.base_url(),
        &mut stop,
    )
    .await;

    let audit = handle.audit_log();
    handle.shutdown().await;
    let cleanup = session.cleanup();
    let denied = audit
        .iter()
        .filter(|r| r.decision == entangle_agent_host::AuditDecision::Deny)
        .count();
    tracing::info!(session = %session_id, tool_calls = audit.len(), denied, "agent session ended");

    if let Err(e) = cleanup {
        // The agent's exit status (or launch error) is still the primary
        // result, but a modified original config is something the operator
        // must see either way.
        eprintln!("warning: {e}");
    }
    outcome
}

/// A project's own MCP config (e.g. `.mcp.json` in the current directory)
/// ships with the repository, so its stdio servers are commands chosen by
/// whoever wrote the repository. The agent would ask before starting them,
/// but in a session it only sees gateway URLs and the gateway starts them,
/// so ask here: list each one and require `--trust-project-servers` or a
/// `y` at a terminal prompt (default No). Env var values are never printed.
/// A config named with `--config` is the user's own choice and is not
/// reported here.
fn confirm_project_servers(session: &AgentSession, trusted: bool) -> Result<()> {
    let servers = session.project_stdio_servers();
    if servers.is_empty() {
        return Ok(());
    }
    let path = match std::env::current_dir() {
        Ok(cwd) if session.source_path().is_relative() => {
            cwd.join(session.source_path()).display().to_string()
        }
        _ => session.source_path().to_string(),
    };
    eprintln!(
        "The project config {path} declares {} MCP server(s) that the gateway would start \
         as commands on this machine:",
        servers.len()
    );
    for (name, spec) in &servers {
        if let McpServerSpec::Stdio { command, args, env } = spec {
            // Debug formatting quotes and escapes everything, so a name or
            // argument cannot hide itself with terminal control sequences.
            let env_names: Vec<&String> = env.keys().collect();
            eprintln!("  {name:?}: command {command:?}, args {args:?}, env vars {env_names:?}");
        }
    }
    if trusted {
        return Ok(());
    }
    if std::io::stdin().is_terminal() {
        eprint!("Start these servers? [y/N] ");
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .context("reading the answer")?;
        if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            return Ok(());
        }
        bail!("not starting the MCP servers of the project config {path}: declined");
    }
    bail!(
        "refusing to start the MCP servers of the project config {path} without consent: \
         re-run with --trust-project-servers to start them, or run in a terminal and answer \
         the prompt"
    )
}

async fn launch(
    session: &mut AgentSession,
    args: &RunArgs,
    session_id: &str,
    token: &str,
    base_url: &str,
    stop: &mut tokio::sync::watch::Receiver<Option<Stop>>,
) -> Result<i32> {
    // `activate` creates the directory (mode 0700, missing parents too) and
    // owns it: it is removed if activation fails and by `cleanup` otherwise.
    let dir = utf8(sessions_root().join(session_id))?;
    let plan = session
        .activate(&dir, base_url, TOKEN_ENV)
        .context("writing session config")?
        .clone();

    if let Some(stop) = *stop.borrow() {
        // Asked to stop before the agent started: do not start it.
        return Ok(stop.exit_code());
    }
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

    // Interactive agents use Ctrl-C to interrupt the current turn, not to
    // quit, so SIGINT never ends the session: the agent decides what it means
    // and the session lasts until the agent exits. At a terminal the agent
    // already got the SIGINT (the terminal signals the whole foreground
    // process group), so it is not sent again — many agents treat a second
    // Ctrl-C as "quit now". Without a terminal the signal reached the CLI
    // alone, so it is passed on. SIGTERM and SIGHUP are always passed on,
    // and an agent that ignores them is killed after STOP_GRACE.
    let interactive = std::io::stdin().is_terminal();
    loop {
        tokio::select! {
            status = child.wait() => return Ok(exit_code(status.context("waiting for agent")?)),
            stop = next_signal(stop) => {
                if stop == Stop::Interrupt {
                    if !interactive {
                        forward_signal(&child, stop);
                    }
                    continue;
                }
                forward_signal(&child, stop);
                if let Ok(status) = tokio::time::timeout(STOP_GRACE, child.wait()).await {
                    return Ok(exit_code(status.context("waiting for agent")?));
                }
                let _ = child.kill().await;
                return Ok(stop.exit_code());
            }
        }
    }
}
