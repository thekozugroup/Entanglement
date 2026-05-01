//! `entangled` — the Entanglement daemon binary.
//!
//! Phase-1: foreground-only process. Manages the runtime kernel and serves a
//! Unix-domain-socket JSON-RPC 2.0 interface for the CLI and operators.

use anyhow::Context;
use clap::{Parser, Subcommand};
use entangle_bin::{config, maintenance::MaintenanceLoop, server, state::DaemonState};
use entangle_mesh_local::{Discovery, DiscoveryConfig, HardwareAdvert, LocalPeer};
use entangle_peers::PeerStore;
use entangle_runtime::{Kernel, KernelConfig};
use entangle_scheduler::{Dispatcher, WorkerPool};
use entangle_signing::{IdentityKeyPair, Keyring};
use std::path::{Path, PathBuf};
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
    entangle_observability::init_default();

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

    // ── 2b. Identity keypair ──────────────────────────────────────────────────
    let identity_path = config_dir.join("identity.key");
    let identity = ensure_identity(&identity_path)
        .with_context(|| format!("loading/creating identity from {}", identity_path.display()))?;

    // ── 2c. Peer store ────────────────────────────────────────────────────────
    let peer_store =
        PeerStore::open(config_dir.join("peers.toml")).context("opening peer store")?;

    // ── 3. Build kernel ───────────────────────────────────────────────────────
    let kernel_cfg = KernelConfig {
        multi_node: cfg.runtime.multi_node,
        bus_capacity: cfg.runtime.bus_capacity,
        ..KernelConfig::default()
    };
    let kernel = Arc::new(Kernel::new(kernel_cfg, keyring).context("initializing runtime kernel")?);

    // ── 3b. Worker pool + Dispatcher ─────────────────────────────────────────
    let worker_pool = WorkerPool::new();
    let local_peer_id =
        entangle_types::peer_id::PeerId::from_public_key_bytes(identity.public().as_bytes());
    let dispatcher = Arc::new(Dispatcher::new(
        worker_pool.clone(),
        kernel.clone(),
        local_peer_id,
    ));

    // ── 3c. Assemble shared DaemonState ──────────────────────────────────────
    let display_name = std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_owned()))
        .unwrap_or_else(|_| "entangled".to_owned());
    let mut daemon_state = DaemonState::new(
        kernel.clone(),
        dispatcher,
        worker_pool,
        peer_store,
        identity,
        display_name,
    );

    // ── 3d. Spawn mDNS discovery (when `mesh.local` transport is configured) ─
    // The discovery handle is stored in DaemonState so RPC handlers can call
    // `snapshot_peers()` directly.
    let _discovery_browser_handle = if cfg.mesh.transports.iter().any(|t| t == "local") {
        let local = LocalPeer {
            peer_id: daemon_state.local_peer_id,
            display_name: daemon_state.local_display_name.clone(),
            port: 7001, // Phase 1 placeholder; real port wiring is Phase 2 transport
            version: env!("CARGO_PKG_VERSION").into(),
            hardware: Some(detect_hardware()),
        };
        let discovery_cfg = DiscoveryConfig {
            local,
            announce_interval_secs: 30,
            channel_capacity: 256,
        };
        match Discovery::new(discovery_cfg) {
            Ok(d) => {
                if let Err(e) = d.start_announcing() {
                    tracing::warn!(error = %e, "mDNS announce failed — discovery disabled");
                    None
                } else {
                    let browser_handle = d.spawn_browser().ok();
                    let d = Arc::new(d);
                    daemon_state.set_discovery(d.clone());

                    // Worker-pool feeder: forward DiscoveryEvents into WorkerPool.
                    let pool = daemon_state.worker_pool.clone();
                    let mut sub = d.subscribe();
                    let local_peer = daemon_state.local_peer_id;
                    tokio::spawn(async move {
                        use entangle_mesh_local::DiscoveryEvent;
                        use entangle_scheduler::WorkerInfo;
                        use entangle_types::resource::GpuRequirement;

                        while let Ok(evt) = sub.recv().await {
                            match evt {
                                DiscoveryEvent::PeerAppeared(p)
                                | DiscoveryEvent::PeerUpdated(p) => {
                                    if p.peer_id == local_peer {
                                        continue;
                                    }
                                    if let Some(hw) = &p.hardware {
                                        pool.upsert(WorkerInfo {
                                            peer_id: p.peer_id,
                                            display_name: p.display_name.clone(),
                                            cpu_cores: hw.cpu_cores,
                                            memory_bytes: hw.memory_bytes,
                                            gpu: hw.gpu_backend.map(|backend| GpuRequirement {
                                                vram_min_bytes: hw.gpu_vram_bytes,
                                                backend,
                                            }),
                                            npu: None, // Phase 2: NPU advertisement
                                            network_bandwidth_bps: hw.network_bandwidth_bps,
                                            rtt_ms: 5, // Phase 1 estimate; real RTT in Phase 2
                                            load: 0.0,
                                            cost: 1.0,
                                        });
                                    }
                                }
                                DiscoveryEvent::PeerDisappeared { peer_id, .. } => {
                                    pool.remove(&peer_id);
                                }
                            }
                        }
                    });
                    browser_handle
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "Discovery::new failed — discovery disabled");
                None
            }
        }
    } else {
        None
    };

    let state = Arc::new(daemon_state);

    tracing::info!(
        local_peer_id = %state.local_peer_id,
        "daemon identity ready",
    );

    // ── 4. Shutdown channel (shared with maintenance loop) ────────────────────
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // ── 5. Spawn maintenance loop ─────────────────────────────────────────────
    let maint = MaintenanceLoop::new(Default::default());
    let maint_task = tokio::spawn(maint.run(shutdown_rx.clone()));

    // ── 6. Bind socket and spawn RPC accept loop ──────────────────────────────
    let socket_path_clone = socket_path.clone();
    let state_clone = state.clone();
    let rpc_task = tokio::spawn(async move {
        if let Err(e) = server::serve(socket_path_clone, state_clone).await {
            tracing::error!(error = %e, "RPC server fatal error");
        }
    });

    // ── 7. Block on shutdown signal ───────────────────────────────────────────
    wait_for_shutdown().await;

    tracing::info!("shutting down entangled");

    // Signal the maintenance loop (and any other watchers) to stop.
    shutdown_tx.send(true).ok();

    // Abort the accept loop; in-flight client tasks will finish naturally.
    rpc_task.abort();
    let _ = rpc_task.await;
    let _ = maint_task.await;

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

// ── Identity helper ───────────────────────────────────────────────────────────

/// Best-effort detection of local hardware for mDNS advertisement.
///
/// Phase 1: only CPU core count is reliable.  Memory, GPU, and network
/// bandwidth are stubbed at 0 and will be filled in Phase 2 via `sysinfo`
/// and `wgpu` probing.
fn detect_hardware() -> HardwareAdvert {
    HardwareAdvert {
        cpu_cores: num_cpus::get() as f32,
        memory_bytes: 0,   // Phase 2: sysinfo crate
        gpu_backend: None, // Phase 2: wgpu detection
        gpu_vram_bytes: 0,
        network_bandwidth_bps: 0,
    }
}

/// Load the identity keypair from `path`, or generate and persist a new one.
///
/// The file is written with mode `0600` on Unix so only the owning user can
/// read the private key material.
fn ensure_identity(path: &Path) -> anyhow::Result<IdentityKeyPair> {
    if path.exists() {
        let pem = std::fs::read_to_string(path).context("read identity.key")?;
        IdentityKeyPair::from_pem(&pem)
            .context("parse identity.key")
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    } else {
        let kp = IdentityKeyPair::generate();
        let pem = kp.to_pem();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, &pem)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }
        Ok(kp)
    }
}
