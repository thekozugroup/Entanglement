//! `entangled` — the Entanglement daemon binary.
//!
//! Phase-1: foreground-only process. Manages the runtime kernel and serves a
//! Unix-domain-socket JSON-RPC 2.0 interface for the CLI and operators.

use anyhow::Context;
use clap::{Parser, Subcommand};
use entangle_bin::{config, server};
use entangle_runtime::{Kernel, KernelConfig};
use entangle_signing::Keyring;
use std::path::PathBuf;
use std::sync::Arc;

// ── CLI definition ────────────────────────────────────────────────────────────

/// The Entanglement daemon — manages plugins and serves operator RPC.
#[derive(Parser, Debug)]
#[command(name = "entangled", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Start the daemon (Phase 1: always foreground).
    Run(RunArgs),
    /// Connect to a running daemon and print its status.
    Status(StatusArgs),
}

#[derive(Parser, Debug)]
struct RunArgs {
    /// Do not daemonize; run in the foreground (Phase-1 default and only mode).
    #[arg(long, default_value_t = true)]
    foreground: bool,

    /// Override the Unix-domain-socket path.
    #[arg(long)]
    socket: Option<PathBuf>,
}

#[derive(Parser, Debug)]
struct StatusArgs {
    /// Socket path of the running daemon.
    #[arg(long)]
    socket: Option<PathBuf>,
}

// ── entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Run(args) => run(args).await,
        Command::Status(args) => status(args).await,
    }
}

// ── `run` subcommand ──────────────────────────────────────────────────────────

#[cfg(not(unix))]
async fn run(_args: RunArgs) -> anyhow::Result<()> {
    anyhow::bail!("entangled requires Unix in Phase 1; WSL2 is supported on Windows.")
}

#[cfg(unix)]
async fn run(args: RunArgs) -> anyhow::Result<()> {
    // ── 1. Tracing setup ──────────────────────────────────────────────────────
    init_tracing();

    let socket_path = args.socket.unwrap_or_else(config::default_socket_path);
    let config_dir = config::default_config_dir();
    let config_path = config_dir.join("config.toml");
    let keyring_path = config_dir.join("keyring.toml");

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        socket = %socket_path.display(),
        pid = std::process::id(),
        "entangled starting",
    );

    // ── 2. Load config + keyring ──────────────────────────────────────────────
    let cfg = config::load_config(&config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;

    let keyring = if keyring_path.exists() {
        Keyring::load(&keyring_path)
            .with_context(|| format!("loading keyring from {}", keyring_path.display()))?
    } else {
        tracing::debug!("keyring file absent — starting with empty keyring");
        Keyring::new()
    };

    // ── 3. Build kernel ───────────────────────────────────────────────────────
    let kernel_cfg = KernelConfig {
        multi_node: cfg.runtime.multi_node,
        bus_capacity: cfg.runtime.bus_capacity,
        ..KernelConfig::default()
    };
    let kernel = Arc::new(Kernel::new(kernel_cfg, keyring).context("initializing runtime kernel")?);

    // ── 4 + 5. Bind socket and spawn RPC accept loop ──────────────────────────
    let socket_path_clone = socket_path.clone();
    let kernel_clone = kernel.clone();
    let rpc_task = tokio::spawn(async move {
        if let Err(e) = server::serve(socket_path_clone, kernel_clone).await {
            tracing::error!(error = %e, "RPC server fatal error");
        }
    });

    // ── 6. Block on shutdown signal ───────────────────────────────────────────
    wait_for_shutdown().await;

    tracing::info!("shutting down entangled");

    // Abort the accept loop; in-flight client tasks will finish naturally.
    rpc_task.abort();
    let _ = rpc_task.await;

    // Remove the socket file on clean shutdown.
    let _ = std::fs::remove_file(&socket_path);

    tracing::info!("entangled stopped");
    Ok(())
}

/// Wait for SIGTERM or Ctrl-C (SIGINT).
#[cfg(unix)]
async fn wait_for_shutdown() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received SIGINT");
        }
        _ = sigterm.recv() => {
            tracing::info!("received SIGTERM");
        }
    }
}

// ── `status` subcommand ───────────────────────────────────────────────────────

async fn status(args: StatusArgs) -> anyhow::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    let socket_path = args.socket.unwrap_or_else(config::default_socket_path);

    let mut stream = UnixStream::connect(&socket_path)
        .await
        .with_context(|| format!("connecting to {}", socket_path.display()))?;

    let req = r#"{"jsonrpc":"2.0","id":1,"method":"version","params":{}}"#;
    stream.write_all(req.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    println!("{line}");
    Ok(())
}

// ── tracing initialisation ────────────────────────────────────────────────────

fn init_tracing() {
    use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tokio=warn,wasmtime=warn"));

    // JSON format when stderr is not a TTY (systemd / docker), compact otherwise.
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());

    if is_tty {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().compact().with_writer(std::io::stderr))
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json().with_writer(std::io::stderr))
            .init();
    }
}
