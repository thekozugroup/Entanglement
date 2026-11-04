//! Shared daemon state: the live runtime kernel, dispatcher, mesh discovery,
//! and peer store. Constructed once at daemon startup, shared by all RPC
//! handlers via `Arc<DaemonState>`.

use entangle_mesh_iroh::MeshIroh;
use entangle_mesh_local::Discovery;
use entangle_mesh_tailscale::{LivenessSnapshot, MeshTailscale};
use entangle_observability::Registry;
use entangle_peers::PeerStore;
use entangle_runtime::Kernel;
use entangle_scheduler::{Dispatcher, PeerDirectory, WorkerPool};
use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::watch;

/// The `mesh.tailscale` pieces `diag/mesh` reads.
#[derive(Clone)]
pub struct TailscaleDiag {
    /// The running transport (candidate list, local address).
    pub transport: MeshTailscale,
    /// Confirmed liveness, updated by the poller.
    pub liveness: watch::Receiver<LivenessSnapshot>,
}

/// What the `diag/mesh` report needs to know about the mesh setup. All parts
/// are optional: the report only describes transports that are running.
#[derive(Clone, Default)]
pub struct MeshDiagSources {
    /// `[mesh] transports` as configured.
    pub configured_transports: Vec<String>,
    /// The `mesh.iroh` scheduler endpoint, when started.
    pub iroh: Option<Arc<MeshIroh>>,
    /// Addresses of the peers this node may dispatch to over iroh.
    pub iroh_directory: Option<PeerDirectory>,
    /// The `mesh.tailscale` transport, when started.
    pub tailscale: Option<TailscaleDiag>,
    /// Where the metrics endpoint listens, when enabled.
    pub metrics_listen: Option<SocketAddr>,
}

/// All runtime state the daemon needs to serve RPC requests.
///
/// Constructed once at startup and distributed to every handler via
/// `Arc<DaemonState>`.  All interior fields are either `Arc`-wrapped or
/// cheaply cloneable (`PeerStore` uses `Arc<RwLock<…>>` internally).
#[derive(Clone)]
pub struct DaemonState {
    /// The live plugin runtime kernel.
    pub kernel: Arc<Kernel>,
    /// Shared task dispatcher (wraps the worker pool).
    pub dispatcher: Arc<Dispatcher>,
    /// Worker pool: current view of local/remote compute capacity.
    pub worker_pool: WorkerPool,
    /// Trusted peer allowlist, persisted to `~/.entangle/peers.toml`.
    pub peer_store: PeerStore,
    /// This node's stable identifier (derived from the identity key).
    pub local_peer_id: PeerId,
    /// Human-readable hostname / display name for this node.
    pub local_display_name: String,
    /// Ed25519 identity keypair (signing, pairing).
    pub identity: IdentityKeyPair,
    /// mDNS discovery handle; `None` when `mesh.local` transport is disabled.
    pub discovery: Option<Arc<Discovery>>,
    /// The daemon's metrics registry (shared with the kernel, dispatcher and
    /// the scrape endpoint). A fresh private one unless
    /// [`DaemonState::with_metrics`] is used.
    pub metrics: Registry,
    /// Mesh details for `diag/mesh`.
    pub diag: MeshDiagSources,
    /// When the daemon started (for uptime).
    pub started_at: Instant,
    /// The config.toml whose `[plugins] disabled` list is re-read before each
    /// plugin load; `None` (tests) keeps the kernel's startup list.
    pub config_path: Option<std::path::PathBuf>,
}

impl DaemonState {
    /// Construct `DaemonState` from already-initialised components.
    ///
    /// `local_peer_id` is derived deterministically from
    /// `identity.public().as_bytes()` so callers don't need to pass it
    /// separately.
    pub fn new(
        kernel: Arc<Kernel>,
        dispatcher: Arc<Dispatcher>,
        worker_pool: WorkerPool,
        peer_store: PeerStore,
        identity: IdentityKeyPair,
        display_name: String,
    ) -> Self {
        let local_peer_id = PeerId::from_public_key_bytes(identity.public().as_bytes());
        Self {
            kernel,
            dispatcher,
            worker_pool,
            peer_store,
            local_peer_id,
            local_display_name: display_name,
            identity,
            discovery: None,
            metrics: Registry::new(),
            diag: MeshDiagSources::default(),
            started_at: Instant::now(),
            config_path: None,
        }
    }

    /// Re-read `[plugins] disabled` from `path` before every plugin load.
    #[must_use]
    pub fn with_config_path(mut self, path: std::path::PathBuf) -> Self {
        self.config_path = Some(path);
        self
    }

    /// Use `registry` as the daemon's metrics registry. It should be the same
    /// one the kernel and dispatcher were given.
    #[must_use]
    pub fn with_metrics(mut self, registry: Registry) -> Self {
        self.metrics = registry;
        self
    }

    /// Sync the kernel's disabled-plugin list with config.toml (see
    /// [`DaemonState::with_config_path`]). An unreadable or invalid file keeps
    /// the previous list: a broken edit never re-enables a disabled plugin.
    pub fn refresh_disabled_plugins(&self) {
        let Some(path) = &self.config_path else {
            return;
        };
        match crate::config::load_config(path) {
            Ok(cfg) => self.kernel.set_disabled_plugins(cfg.plugins.disabled),
            Err(e) => tracing::warn!(
                path = %path.display(), error = %e,
                "cannot re-read [plugins] disabled; keeping the previous list"
            ),
        }
    }

    /// Describe the mesh setup for `diag/mesh`.
    #[must_use]
    pub fn with_diag(mut self, diag: MeshDiagSources) -> Self {
        self.diag = diag;
        self
    }

    /// Register the scrape-time collectors for daemon-wide gauges: build
    /// info, uptime and trusted/revoked peer counts. Call once.
    pub fn register_collectors(&self) {
        let peers = self.peer_store.clone();
        let started = self.started_at;
        self.metrics.register_collector(move |r| {
            use entangle_observability::catalog::names;
            use entangle_peers::TrustLevel;
            r.set_gauge(
                "entangle_build_info",
                "Daemon build information (value is always 1)",
                &[("version", env!("CARGO_PKG_VERSION"))],
                1.0,
            );
            r.set_gauge(
                "entangle_daemon_uptime_seconds",
                "Seconds since the daemon started",
                &[],
                started.elapsed().as_secs_f64(),
            );
            let all = peers.list();
            let count = |level: TrustLevel| all.iter().filter(|p| p.trust == level).count();
            for (state, n) in [
                ("trusted", count(TrustLevel::Trusted)),
                ("observer", count(TrustLevel::Observer)),
                ("revoked", count(TrustLevel::Revoked)),
            ] {
                r.set_gauge(
                    names::MESH_PEERS,
                    "Mesh peers by state (trusted, observer and revoked come from the peer store, sighted from mDNS)",
                    &[("state", state)],
                    n as f64,
                );
            }
        });
    }

    /// Attach a running [`Discovery`] handle.  Called after construction when
    /// the `mesh.local` transport is enabled in config.
    pub fn set_discovery(&mut self, d: Arc<Discovery>) {
        self.discovery = Some(d);
    }
}
