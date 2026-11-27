//! Shared daemon state: the live runtime kernel, dispatcher, mesh discovery,
//! and peer store. Constructed once at daemon startup, shared by all RPC
//! handlers via `Arc<DaemonState>`.

use entangle_mesh_local::Discovery;
use entangle_peers::PeerStore;
use entangle_runtime::Kernel;
use entangle_scheduler::{Dispatcher, WorkerPool};
use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;
use std::sync::Arc;

/// All runtime state the daemon needs to serve RPC requests.
///
/// Constructed once at startup and distributed to every handler via
/// `Arc<DaemonState>`.  All interior fields are either `Arc`-wrapped or
/// cheaply cloneable (`PeerStore` uses `Arc<RwLock<…>>` internally).
#[derive(Clone)]
pub struct DaemonState {
    /// Mesh relay sender and optional authorized receiver.
    pub relay: Option<Arc<crate::relay::RelayService>>,
    pub(crate) streams: crate::streams::Sessions,
    /// Operator config file owned by this daemon's control socket.
    pub config_path: Option<std::path::PathBuf>,
    /// Distinguishes reviews issued by a previous daemon process.
    pub policy_session: String,
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
    /// Scheduler transports currently available, refreshed by the route monitor.
    pub scheduler_transports: Option<tokio::sync::watch::Receiver<Vec<String>>>,
    /// mDNS discovery handle; `None` when `mesh.local` transport is disabled.
    pub discovery: Option<Arc<Discovery>>,
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
            config_path: None,
            relay: None,
            streams: Default::default(),
            policy_session: entangle_types::peer_id::PeerId::from_public_key_bytes(
                IdentityKeyPair::generate().public().as_bytes(),
            )
            .to_hex(),
            kernel,
            dispatcher,
            worker_pool,
            peer_store,
            local_peer_id,
            local_display_name: display_name,
            identity,
            scheduler_transports: None,
            discovery: None,
        }
    }

    /// Render a Prometheus snapshot shared by the control socket and HTTP scraper.
    pub fn render_metrics(&self) -> String {
        let metrics = self.kernel.metrics();
        metrics.set_gauge("entangle_daemon_up", "Daemon is serving requests", &[], 1.0);
        metrics.set_gauge(
            "entangle_plugins_loaded",
            "Components currently loaded on this worker",
            &[],
            self.kernel.loaded_plugin_count() as f64,
        );
        metrics.render()
    }

    /// Attach a running [`Discovery`] handle.  Called after construction when
    /// the `mesh.local` transport is enabled in config.
    pub fn set_discovery(&mut self, d: Arc<Discovery>) {
        self.discovery = Some(d);
    }
}
