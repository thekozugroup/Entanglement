//! Shared daemon state: the live runtime kernel, dispatcher, mesh discovery,
//! and peer store. Constructed once at daemon startup, shared by all RPC
//! handlers via `Arc<DaemonState>`.

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
        }
    }
}
