//! `entangled` — the Entanglement daemon binary.
//!
//! Phase-1: foreground-only process. Manages the runtime kernel and serves a
//! Unix-domain-socket JSON-RPC 2.0 interface for the CLI and operators.

use anyhow::Context;
use clap::{Parser, Subcommand};
use entangle_bin::{config, maintenance::MaintenanceLoop, remote, server, state::DaemonState};
use entangle_broker::BrokerPolicy;
use entangle_mesh_iroh::MeshTransport;
use entangle_mesh_local::{
    Discovery, DiscoveryConfig, DiscoveryEvent, HardwareAdvert, LocalPeer, PeerSeen,
    TransportAdvert,
};
use entangle_peers::{PeerStore, TrustLevel};
use entangle_runtime::Kernel;
use entangle_scheduler::{Dispatcher, PeerDirectory, RemoteDispatch, WorkerInfo, WorkerPool};
use entangle_signing::{IdentityKeyPair, Keyring};
use entangle_types::peer_id::PeerId;
use entangle_types::resource::GpuRequirement;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

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
    let socket_path = match args.socket {
        Some(path) => path,
        None => config::default_socket_path().context("resolving default socket path")?,
    };
    let config_dir = config::default_config_dir().context("resolving config directory")?;
    let config_path = config_dir.join("config.toml");
    let keyring_path = config_dir.join("keyring.toml");

    // ── 1. Config, then tracing ──────────────────────────────────────────────
    // The config is read first because `[telemetry.otlp]` decides which
    // layers the global subscriber gets.
    let cfg = config::load_config(&config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;
    let otel_cfg = cfg
        .telemetry
        .otel_config()
        .context("[telemetry.otlp] is invalid")?;
    let otel_exporter =
        entangle_observability::init_with_otel("info,tokio=warn,wasmtime=warn", otel_cfg.as_ref())
            .context("starting the OTLP trace exporter")?;
    // Fault isolation (spec §2.1): from here on a panic outside a contained
    // plugin call logs one `ENTANGLE-E0787` line and exits with status 70
    // (`EXIT_CORE_FAULT`) so the service manager restarts the daemon.
    entangle_core::fault::install_panic_hook();
    let registry = entangle_observability::Registry::new();
    if let Some(exporter) = &otel_exporter {
        exporter.attach_metrics(&registry);
        tracing::info!(
            endpoint = %cfg.telemetry.otlp.endpoint,
            "exporting traces over OTLP/HTTP"
        );
    }

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        socket = %socket_path.display(),
        pid = std::process::id(),
        "entangled starting",
    );

    // ── 2. Load keyring ───────────────────────────────────────────────────────
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

    // ── 2c. Peer store + startup policy ──────────────────────────────────────
    let peer_store =
        PeerStore::open(config_dir.join("peers.toml")).context("opening peer store")?;

    // Refuse to start in multi-node mode with an empty peer allowlist
    // (ENTANGLE-E0050, spec §11 #16) — before any mesh transport activates.
    let startup_policy = BrokerPolicy::new(
        cfg.security.max_tier_allowed,
        cfg.mesh.multi_node,
        &peer_store,
    );
    startup_policy
        .check_startup()
        .context("startup policy check failed (spec §11 #16)")?;

    // ── 3. Build kernel ───────────────────────────────────────────────────────
    let kernel_cfg = config::kernel_config(&cfg, &config_dir);
    if cfg.security.allow_unsandboxed_native {
        tracing::warn!(
            "[security] allow_unsandboxed_native = true: native plugins will run WITHOUT an \
             OS sandbox on hosts that have none"
        );
    }
    let kernel = Arc::new(
        Kernel::new(kernel_cfg, keyring)
            .context("initializing runtime kernel")?
            .with_metrics(registry.clone()),
    );

    // ── 3b. Worker pool + Dispatcher ─────────────────────────────────────────
    let worker_pool = WorkerPool::new();
    let local_peer_id =
        entangle_types::peer_id::PeerId::from_public_key_bytes(identity.public().as_bytes());

    // Optional `mesh.iroh` scheduler transport. Absent it, the dispatcher is
    // local-only and this daemon behaves exactly as a single-machine node.
    let scheduler_mesh = if remote::scheduler_transport_enabled(&cfg.mesh.transports) {
        match remote::start_scheduler_transport(&cfg.scheduler, &identity).await {
            Ok(t) => Some(t),
            Err(e) => {
                // A transport that will not bind is a degraded node, not a
                // dead one: keep serving local work rather than refusing to
                // start.
                tracing::error!(error = %e, "mesh.iroh scheduler transport failed to start — remote dispatch disabled");
                None
            }
        }
    } else {
        None
    };

    // Inbound: one task server and one stream server, shared by every
    // transport that serves the scheduler protocols, gated on the peer
    // store (see `remote::PeerStoreAllowlist`).
    let tailscale_on = entangle_bin::tailscale::enabled(&cfg.mesh);
    let servers = (scheduler_mesh.is_some() || tailscale_on).then(|| {
        entangle_bin::mesh::scheduler_servers(
            kernel.clone(),
            peer_store.clone(),
            identity.clone(),
            Some(registry.clone()),
        )
    });
    // The daemon's long-lived core tasks: any one ending while the daemon
    // runs (returning or panicking) is a fault and exits with status 70
    // rather than leaving a half-working daemon (spec §2.1).
    let mut supervisor = entangle_core::fault::Supervisor::new();
    if let (Some(transport), Some(servers)) = (&scheduler_mesh, &servers) {
        // entangle/scheduler/1 and entangle/stream/1 on the same endpoint.
        for task in entangle_bin::mesh::serve_on_iroh(transport, servers) {
            supervisor.watch("scheduler-server", task);
        }
    }

    // ── 3b'. Optional `mesh.tailscale` transport + liveness poller ────────────
    // Started before the dispatcher (it is one of its outbound transports)
    // and before the shared state (so `diag/mesh` can see it). It serves the
    // same task and stream servers.
    let tailscale_rt = if tailscale_on {
        match entangle_bin::tailscale::start(
            &cfg.mesh,
            &identity,
            peer_store.clone(),
            servers.as_ref().map(|s| Arc::clone(&s.tasks)),
            servers.as_ref().map(|s| Arc::clone(&s.streams)),
            Some(Arc::new(entangle_bin::tailscale::TailnetWorkers::new(
                worker_pool.clone(),
                peer_store.clone(),
                local_peer_id,
            ))),
        )
        .await
        {
            Ok(rt) => {
                // The state gauge exists only while the transport does.
                entangle_bin::tailscale::spawn_state_metrics(registry.clone(), rt.liveness.state());
                Some(rt)
            }
            Err(e) => {
                tracing::error!(error = %e, "mesh.tailscale failed to start — transport disabled");
                None
            }
        }
    } else {
        None
    };

    // Outbound: a router picking a transport per peer (spec §6.1).
    let local_on = cfg.mesh.transports.iter().any(|t| t == "local");
    let iroh_directory = scheduler_mesh
        .as_ref()
        .map(|_| remote::directory_from_config(&cfg.scheduler, &peer_store, local_peer_id));
    let local_sightings = (scheduler_mesh.is_some() && local_on).then(PeerDirectory::new);
    let route_policy = cfg
        .mesh
        .route_policy()
        .context("[mesh] preferred / [mesh.overrides]")?;
    let router = entangle_bin::mesh::build_router(
        local_peer_id,
        entangle_bin::mesh::RouterInputs {
            iroh: scheduler_mesh.clone(),
            iroh_directory: iroh_directory.clone(),
            local_sightings: local_sightings.clone(),
            tailscale: tailscale_rt
                .as_ref()
                .map(|rt| (rt.transport.clone(), rt.liveness.state())),
            policy: route_policy,
            metrics: Some(registry.clone()),
        },
    );
    let mut dispatcher = Dispatcher::new(worker_pool.clone(), kernel.clone(), local_peer_id)
        .with_metrics(registry.clone())
        .with_spot_checks(cfg.scheduler.spot_checks());
    if let Some(router) = router {
        let running = router.transports();
        tracing::info!(
            transports = ?running.iter().map(|k| k.as_str()).collect::<Vec<_>>(),
            preferred = cfg.mesh.preferred.as_deref().unwrap_or("-"),
            overrides = cfg.mesh.overrides.len(),
            "remote dispatch enabled"
        );
        entangle_bin::mesh::warn_unavailable_choices(&cfg.mesh, &running);
        dispatcher =
            dispatcher.with_remote(Arc::new(RemoteDispatch::with_router(Arc::new(router))));
    }
    let dispatcher = Arc::new(dispatcher);

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
    )
    .with_metrics(registry.clone());
    daemon_state.register_collectors();

    // ── 3d. Spawn mDNS discovery (when `mesh.local` transport is configured) ─
    // The discovery handle is stored in DaemonState so RPC handlers can call
    // `snapshot_peers()` directly; the browser task handle lives inside
    // `Discovery` and is stopped by `Discovery::shutdown` on daemon exit.
    if cfg.mesh.transports.iter().any(|t| t == "local") {
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
        // Advertise the scheduler endpoint's key and port, so trusted peers
        // on the LAN can dial it directly (`mesh.local`).
        let advert = scheduler_mesh.as_ref().and_then(|t| {
            t.local_addrs()
                .first()
                .map(|a| TransportAdvert::new(t.local_public_key(), a.port()))
        });
        match Discovery::new(discovery_cfg).map(|d| match advert {
            Some(a) => d.with_transport_advert(a),
            None => d,
        }) {
            Ok(d) => {
                if let Err(e) = d.start_announcing() {
                    tracing::warn!(error = %e, "mDNS announce failed — discovery disabled");
                } else {
                    if let Err(e) = d.spawn_browser() {
                        tracing::warn!(error = %e, "mDNS browse failed — peer discovery degraded");
                    }
                    let d = Arc::new(d);
                    daemon_state.set_discovery(d.clone());
                    spawn_discovery_feeder(
                        d,
                        daemon_state.worker_pool.clone(),
                        daemon_state.peer_store.clone(),
                        daemon_state.local_peer_id,
                        registry.clone(),
                        local_sightings.clone(),
                    );
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "Discovery::new failed — discovery disabled");
            }
        }
    }

    // ── 3e. Metrics endpoint (fails the start on a bad `[metrics]` section) ──
    let metrics_server =
        entangle_bin::metrics_server::MetricsServer::start(&cfg.metrics, registry.clone())
            .await
            .context("starting the metrics endpoint")?;

    // ── 3e'. Plugin state (spec §2.1): reload what was loaded before the
    // daemon stopped, through the normal load path, before serving RPC.
    let plugin_state = Arc::new(entangle_bin::plugin_state::PluginStateStore::new(
        config_dir.join(entangle_bin::plugin_state::STATE_FILE),
    ));
    entangle_bin::plugin_state::restore(&kernel, &plugin_state, Some(&registry)).await;
    daemon_state = daemon_state.with_plugin_state(plugin_state);

    daemon_state = daemon_state.with_config_path(config_path.clone());
    daemon_state = daemon_state.with_diag(entangle_bin::state::MeshDiagSources {
        configured_transports: cfg.mesh.transports.clone(),
        iroh: scheduler_mesh.clone(),
        iroh_directory,
        tailscale: tailscale_rt
            .as_ref()
            .map(|rt| entangle_bin::state::TailscaleDiag {
                transport: rt.transport.clone(),
                liveness: rt.liveness.state(),
            }),
        metrics_listen: metrics_server.as_ref().map(|m| m.local_addr()),
    });

    let state = Arc::new(daemon_state);

    tracing::info!(
        local_peer_id = %state.local_peer_id,
        "daemon identity ready",
    );

    // ── 4. Shutdown channel (shared with maintenance loop) ────────────────────
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // ── 5. Spawn maintenance loop ─────────────────────────────────────────────
    let maint = MaintenanceLoop::new(Default::default())
        .with_worker_pool(state.worker_pool.clone())
        .with_aot_cache(state.kernel.aot_cache());
    supervisor.spawn("maintenance", maint.run(shutdown_rx.clone()));

    // ── 6. Bind socket and spawn RPC accept loop ──────────────────────────────
    let socket_path_clone = socket_path.clone();
    let state_clone = state.clone();
    entangle_core::fault::remove_on_fault_exit(socket_path.clone());
    supervisor.spawn("rpc-server", async move {
        if let Err(e) = server::serve(socket_path_clone, state_clone).await {
            tracing::error!(error = %e, "RPC server fatal error");
        }
    });

    // ── 7. Block on shutdown signal (or a core task ending) ──────────────────
    tokio::select! {
        () = wait_for_shutdown() => {}
        // Exits with status 70, removing the socket (registered above; the
        // next start would replace a stale one anyway).
        ended = supervisor.next_ended() => ended.exit(),
    }

    tracing::info!("shutting down entangled");

    // Signal the maintenance loop (and any other watchers) to stop.
    shutdown_tx.send(true).ok();

    // Stop the core tasks: the accept loop is aborted (in-flight client
    // tasks finish naturally), the maintenance loop has been told to stop.
    supervisor.shutdown().await;

    // Close the scheduler endpoint, flushing connection-close frames so peers
    // see a deliberate shutdown rather than a timeout. This also terminates
    // the accept loop (`accept` yields `Ok(None)` once closed).
    if let Some(transport) = &scheduler_mesh {
        transport.shutdown().await;
    }

    if let Some(rt) = &tailscale_rt {
        rt.shutdown().await;
    }
    if let Some(server) = metrics_server {
        server.shutdown().await;
    }

    // Unregister from mDNS (sends a goodbye) and stop the browse task so
    // peers drop us promptly instead of waiting for their TTL to expire.
    if let Some(d) = &state.discovery {
        if let Err(e) = d.shutdown() {
            tracing::warn!(error = %e, "mDNS discovery shutdown failed");
        }
    }

    // Remove the socket file on clean shutdown.
    let _ = std::fs::remove_file(&socket_path);

    tracing::info!("entangled stopped");
    // Last: deliver the final span batches. `shutdown` blocks for at most the
    // exporter's request timeout plus one second (spans still unsent then
    // are dropped and counted), so run it off the async worker threads.
    if let Some(exporter) = otel_exporter {
        if let Err(e) = tokio::task::spawn_blocking(move || exporter.shutdown()).await {
            tracing::warn!(error = %e, "OTLP exporter shutdown task failed");
        }
    }
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

    let socket_path = match args.socket {
        Some(path) => path,
        None => config::default_socket_path().context("resolving default socket path")?,
    };

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

// ── Discovery → worker-pool feeder ────────────────────────────────────────────

/// Forward mDNS [`DiscoveryEvent`]s into the scheduler's [`WorkerPool`].
///
/// **Trust gate:** mDNS sightings are unauthenticated, so only peers present
/// in the trusted peer store with trust ≠ [`TrustLevel::Revoked`] are admitted
/// to the pool. The full unauthenticated sighting list stays available for
/// display/status via [`Discovery::snapshot_peers`] — it never feeds placement.
///
/// **Resilience:** a `Lagged` receive error (event backlog overflow under
/// bursty mDNS traffic) is recoverable — the pool is resynced authoritatively
/// from [`Discovery::snapshot_peers`] and the loop continues. Only `Closed`
/// (discovery handle dropped) terminates the feeder.
fn spawn_discovery_feeder(
    discovery: Arc<Discovery>,
    pool: WorkerPool,
    peer_store: PeerStore,
    local_peer: PeerId,
    registry: entangle_observability::Registry,
    sightings: Option<PeerDirectory>,
) {
    let mut sub = discovery.subscribe();
    tokio::spawn(async move {
        use tokio::sync::broadcast::error::RecvError;

        loop {
            match sub.recv().await {
                Ok(evt) => {
                    if let Some(dir) = &sightings {
                        entangle_bin::mesh::track_sighting(dir, &evt, &peer_store, local_peer);
                    }
                    apply_discovery_event(evt, &pool, &peer_store, local_peer);
                    record_sightings(&discovery, &registry).await;
                }
                Err(RecvError::Lagged(skipped)) => {
                    tracing::warn!(
                        skipped,
                        "discovery feeder lagged — resyncing worker pool from snapshot"
                    );
                    let snapshot = discovery.snapshot_peers().await;
                    if let Some(dir) = &sightings {
                        entangle_bin::mesh::resync_sightings(
                            dir,
                            &snapshot,
                            &peer_store,
                            local_peer,
                        );
                    }
                    resync_pool_from_snapshot(&snapshot, &pool, &peer_store, local_peer);
                    record_sightings(&discovery, &registry).await;
                }
                Err(RecvError::Closed) => break,
            }
        }
        tracing::debug!("discovery feeder stopped (event channel closed)");
    });
}

/// Publish the current number of mDNS sightings (trusted or not).
async fn record_sightings(discovery: &Discovery, registry: &entangle_observability::Registry) {
    registry.set_gauge(
        entangle_observability::catalog::names::MESH_PEERS,
        "Mesh peers by state (trusted and revoked come from the peer store, sighted from mDNS)",
        &[("state", "sighted")],
        discovery.peer_count().await as f64,
    );
}

/// Apply a single discovery event to the worker pool (trust-gated).
fn apply_discovery_event(
    evt: DiscoveryEvent,
    pool: &WorkerPool,
    peer_store: &PeerStore,
    local_peer: PeerId,
) {
    match evt {
        DiscoveryEvent::PeerAppeared(p) | DiscoveryEvent::PeerUpdated(p) => {
            if p.peer_id == local_peer {
                return;
            }
            if !is_trusted(peer_store, &p.peer_id) {
                tracing::debug!(
                    peer_id = %p.peer_id,
                    "ignoring untrusted mDNS sighting for worker pool"
                );
                return;
            }
            if let Some(info) = worker_info_from_sighting(&p) {
                pool.upsert(info);
            }
        }
        DiscoveryEvent::PeerDisappeared { peer_id, .. } => {
            pool.remove(&peer_id);
        }
    }
}

/// `true` when `peer_id` is in the allowlist and not revoked.
fn is_trusted(peer_store: &PeerStore, peer_id: &PeerId) -> bool {
    matches!(peer_store.get(peer_id), Some(p) if p.trust != TrustLevel::Revoked)
}

/// Convert an mDNS sighting into a [`WorkerInfo`], or `None` when the peer
/// advertises no hardware (nothing to schedule onto).
fn worker_info_from_sighting(p: &PeerSeen) -> Option<WorkerInfo> {
    let hw = p.hardware.as_ref()?;
    Some(WorkerInfo {
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
    })
}

/// Authoritatively rebuild the worker pool from a discovery snapshot after
/// the event stream lagged: entries absent from (or no longer trusted in) the
/// snapshot are removed, and every trusted sighting is (re-)upserted.
fn resync_pool_from_snapshot(
    snapshot: &[PeerSeen],
    pool: &WorkerPool,
    peer_store: &PeerStore,
    local_peer: PeerId,
) {
    let desired: HashMap<PeerId, WorkerInfo> = snapshot
        .iter()
        .filter(|p| p.peer_id != local_peer && is_trusted(peer_store, &p.peer_id))
        .filter_map(|p| worker_info_from_sighting(p).map(|w| (p.peer_id, w)))
        .collect();

    // `Duration::MAX` TTL = every entry currently in the pool, expired or not.
    for existing in pool.live(Duration::MAX) {
        if !desired.contains_key(&existing.peer_id) {
            pool.remove(&existing.peer_id);
        }
    }
    for info in desired.into_values() {
        pool.upsert(info);
    }
}

// ── Identity helper ───────────────────────────────────────────────────────────

/// Best-effort detection of local hardware for mDNS advertisement.
///
/// Delegates to [`entangle_mesh_local::hardware::detect`], which reads CPU
/// count, total memory, the best GPU (backend + VRAM) and any NPU from
/// sysfs/procfs on Linux and `sysctl` on macOS. Fields it cannot determine
/// stay at their "unknown" values; network bandwidth is not measured.
fn detect_hardware() -> HardwareAdvert {
    entangle_mesh_local::hardware::detect()
}

/// Load the identity keypair from `path`, or generate and persist a new one.
///
/// The file is created with `O_CREAT | O_EXCL` and mode `0600` in a single
/// `open(2)` call, so the private key is never world-readable — not even for
/// the instant between `write` and a follow-up `chmod` — and a concurrent
/// daemon racing us fails loudly instead of clobbering the key. All I/O
/// errors propagate; nothing about key persistence is best-effort.
fn ensure_identity(path: &Path) -> anyhow::Result<IdentityKeyPair> {
    if path.exists() {
        let pem = std::fs::read_to_string(path).context("read identity.key")?;
        return IdentityKeyPair::from_pem(&pem)
            .map_err(|e| anyhow::anyhow!("parse identity.key: {e}"));
    }

    let kp = IdentityKeyPair::generate();
    let pem = kp.to_pem();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating directory {}", parent.display()))?;
    }

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .with_context(|| format!("creating {} (mode 0600, exclusive)", path.display()))?;

    use std::io::Write as _;
    file.write_all(pem.as_bytes())
        .context("write identity.key")?;
    file.sync_all().context("sync identity.key")?;
    Ok(kp)
}

#[cfg(test)]
mod identity_tests {
    use super::*;

    #[test]
    fn ensure_identity_creates_with_mode_0600_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("identity.key");

        let kp1 = ensure_identity(&path).expect("generate identity");
        assert!(path.exists(), "identity.key must be persisted");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "identity.key must be owner-only from creation");
        }

        // Second call loads the same key instead of regenerating.
        let kp2 = ensure_identity(&path).expect("reload identity");
        assert_eq!(
            kp1.public().as_bytes(),
            kp2.public().as_bytes(),
            "reload must yield the same keypair"
        );
    }

    #[test]
    fn ensure_identity_propagates_unwritable_parent_error() {
        // A parent that is a *file* makes create_dir_all fail — the error must
        // propagate instead of being swallowed.
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"not a dir").unwrap();
        let path = blocker.join("identity.key");
        assert!(ensure_identity(&path).is_err());
    }

    #[test]
    fn ensure_identity_corrupt_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        std::fs::write(&path, b"not a pem").unwrap();
        assert!(ensure_identity(&path).is_err());
    }
}
