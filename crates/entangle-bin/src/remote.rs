//! Cross-node scheduler wiring for the daemon.
//!
//! Two halves, enabled by `"iroh"` or `"tailscale"` in `[mesh] transports`:
//!
//! * **server** — [`spawn_task_server`] serves
//!   [`ALPN_SCHEDULER`] so trusted peers
//!   can run work on this node's kernel;
//! * **client** — [`prepare_scheduler`] turns configured peer addresses
//!   into an address book so this node can send work out.
//!
//! # The authorization gate
//!
//! [`PeerStoreAllowlist`] is the only thing standing between the network and
//! this machine's plugin runtime, so it is deliberately tiny and fails closed.
//! A peer may submit work **only** if:
//!
//! 1. the mesh transport authenticated its `PeerId` — iroh derives it from the
//!    Ed25519 key the peer proved possession of during the QUIC handshake, so
//!    it is not a claim the peer makes in its payload; **and**
//! 2. that exact `PeerId` is present in the persisted `PeerStore` (the
//!    `entangle mesh trust` allowlist); **and**
//! 3. its trust level is [`Trusted`](entangle_peers::TrustLevel::Trusted).
//!
//! Anything else — unknown peer, revoked peer, empty store — is refused
//! before the request payload is even parsed. A node that has paired with
//! nobody executes work for nobody.

mod routes;
pub use routes::{prepare_scheduler, LanRoutes, PreparedScheduler};

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use entangle_mesh_iroh::{
    parse_node_addr, IrohPeer, MeshIroh, MeshIrohConfig, MeshTransport, ALPN_SCHEDULER,
};
use entangle_peers::PeerStore;
use entangle_runtime::Kernel;
use entangle_scheduler::{PeerAllowlist, PeerDirectory, RemoteTaskServer, WorkerInfo};
use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;

use crate::config::SchedulerConfig;

/// `true` when the daemon should run a scheduler transport.
///
/// Mirrors how the `"local"` (mDNS) transport is selected: a transport is on
/// only when it is named in `[mesh] transports`. Absent that, this whole
/// module does nothing and the daemon behaves exactly as a single-machine
/// node.
pub fn scheduler_transport_enabled(transports: &[String]) -> bool {
    transports
        .iter()
        .any(|t| matches!(t.as_str(), "iroh" | "tailscale"))
}

/// The daemon's [`PeerAllowlist`]: the persisted, operator-curated peer store.
///
/// See the module docs — this is the authorization gate for remote execution.
#[derive(Clone)]
pub struct PeerStoreAllowlist {
    store: PeerStore,
}

impl PeerStoreAllowlist {
    /// Gate remote execution on `store`.
    pub fn new(store: PeerStore) -> Self {
        Self { store }
    }
}

impl std::fmt::Debug for PeerStoreAllowlist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerStoreAllowlist")
            .field("active_peers", &self.store.active_count())
            .finish()
    }
}

impl PeerAllowlist for PeerStoreAllowlist {
    fn is_authorized(&self, peer: &PeerId) -> bool {
        self.store.is_currently_trusted(peer)
    }
}

/// Start the QUIC endpoint that carries scheduler traffic.
///
/// Bound to `cfg.bind` and speaking [`ALPN_SCHEDULER`] — never
/// `ALPN_CONTROL`, so scheduler traffic cannot arrive on, or be confused
/// with, the membership protocol.
pub async fn start_scheduler_transport(
    cfg: &SchedulerConfig,
    identity: &IdentityKeyPair,
) -> anyhow::Result<Arc<MeshIroh>> {
    bind_scheduler(parse_bind(cfg)?, cfg.relay, identity).await
}

fn parse_bind(cfg: &SchedulerConfig) -> anyhow::Result<SocketAddr> {
    cfg.bind
        .parse()
        .map_err(|e| anyhow::anyhow!("[scheduler] bind = {:?} is not host:port: {e}", cfg.bind))
}

async fn bind_scheduler(
    bind: SocketAddr,
    relay: bool,
    identity: &IdentityKeyPair,
) -> anyhow::Result<Arc<MeshIroh>> {
    let transport = MeshIroh::start(
        MeshIrohConfig {
            bind,
            allow_derp_relay: relay,
            alpn: ALPN_SCHEDULER.to_vec(),
            ..MeshIrohConfig::default()
        },
        identity,
    )
    .await?;

    tracing::info!(
        peer_id = %transport.local_peer_id(),
        addrs = ?transport.local_addrs(),
        relay,
        "mesh.iroh scheduler transport listening",
    );
    Ok(Arc::new(transport))
}

/// Serve scheduler work on `transport` for peers `store` authorizes.
///
/// Returns the join handle of the accept loop. The loop exits when the
/// transport is shut down.
pub fn spawn_task_server(
    transport: Arc<MeshIroh>,
    kernel: Arc<Kernel>,
    store: PeerStore,
    local_peer_id: PeerId,
) -> tokio::task::JoinHandle<()> {
    let allowlist = Arc::new(PeerStoreAllowlist::new(store));
    let server = Arc::new(RemoteTaskServer::new(kernel, allowlist, local_peer_id));
    tokio::spawn(entangle_scheduler::serve_tasks(transport, server))
}

/// Serve scheduler work and report local capacity to currently trusted peers.
pub fn spawn_task_server_with_capabilities(
    transport: Arc<MeshIroh>,
    kernel: Arc<Kernel>,
    store: PeerStore,
    local_peer_id: PeerId,
    capabilities: WorkerInfo,
) -> tokio::task::JoinHandle<()> {
    let allowlist = Arc::new(PeerStoreAllowlist::new(store));
    let server =
        RemoteTaskServer::new(kernel, allowlist, local_peer_id).with_capabilities(capabilities);
    tokio::spawn(entangle_scheduler::serve_tasks(transport, Arc::new(server)))
}

/// Start both one-shot and signed streaming work using this daemon's own identity.
pub fn spawn_streaming_task_server(
    transport: Arc<MeshIroh>,
    kernel: Arc<Kernel>,
    store: PeerStore,
    capabilities: WorkerInfo,
    identity: IdentityKeyPair,
    inference: Option<&crate::config::InferenceConfig>,
    bridge: Option<Arc<dyn entangle_scheduler::relay::RelayHandler>>,
) -> tokio::task::JoinHandle<()> {
    let mut executor: Arc<dyn entangle_scheduler::stream::StreamExecutor> = kernel.clone();
    if let Some(config) = inference {
        match crate::inference::Inference::new(config, &identity, kernel.clone()) {
            Ok(provider) => {
                tracing::info!(plugin = %provider.id(), "configured local inference stream adapter");
                executor = Arc::new(provider);
            }
            Err(error) => {
                tracing::warn!(%error, "local inference disabled by invalid configuration");
            }
        }
    }
    let server = RemoteTaskServer::new(
        kernel,
        Arc::new(PeerStoreAllowlist::new(store)),
        capabilities.peer_id,
    )
    .with_capabilities(capabilities)
    .with_stream_executor(identity, executor)
    .with_relay_handler(bridge);
    tokio::spawn(entangle_scheduler::serve_tasks(transport, Arc::new(server)))
}

/// Build the outbound address book from `[scheduler] peers`.
///
/// Each entry is a `<pubkey-hex>@host:port` long address, the same form
/// `entangle mesh peers` prints. An entry is admitted only if the peer it
/// names is **also** trusted in the peer store: this node dispatches work
/// only to machines the operator has paired with, so a stale or hostile
/// config line cannot by itself redirect work to a stranger.
///
/// Unparseable and untrusted entries are logged and skipped rather than
/// failing startup — one bad line should not take the daemon down.
pub fn directory_from_config(
    cfg: &SchedulerConfig,
    store: &PeerStore,
    local_peer_id: PeerId,
) -> PeerDirectory {
    let directory = PeerDirectory::new();
    for peer in configured_peers(cfg, local_peer_id).into_values() {
        if store.is_currently_trusted(&peer.peer_id) {
            directory.insert(peer);
        } else {
            tracing::warn!(peer_id = %peer.peer_id, "[scheduler] peers: skipping untrusted peer");
        }
    }
    directory
}

fn configured_peers(cfg: &SchedulerConfig, local_peer_id: PeerId) -> HashMap<PeerId, IrohPeer> {
    let mut peers = HashMap::new();
    for entry in &cfg.peers {
        match parse_node_addr(entry) {
            Ok(peer) if peer.peer_id != local_peer_id => {
                peers
                    .entry(peer.peer_id)
                    .and_modify(|known: &mut IrohPeer| known.add_addr(peer.addr))
                    .or_insert(peer);
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, "[scheduler] peers: skipping unparseable address");
            }
        }
    }
    peers
}

#[cfg(test)]
mod tests {
    use super::*;
    use entangle_peers::TrustedPeer;
    use entangle_scheduler::PeerAddressBook;

    fn peer_id(byte: u8) -> PeerId {
        PeerId::from_public_key_bytes(&[byte; 32])
    }

    fn trusted(store: &PeerStore, id: PeerId) {
        store
            .add(TrustedPeer::new(id, hex::encode([0u8; 32]), "node".into()))
            .expect("in-memory add");
    }

    #[test]
    fn transport_is_off_unless_explicitly_named() {
        assert!(!scheduler_transport_enabled(&[]));
        assert!(!scheduler_transport_enabled(&["local".to_owned()]));
        assert!(scheduler_transport_enabled(&["tailscale".to_owned()]));
        assert!(scheduler_transport_enabled(&[
            "local".to_owned(),
            "iroh".to_owned()
        ]));
    }

    /// An empty store authorizes nobody. This is the state a freshly
    /// installed daemon is in, and it must not execute work for anyone.
    #[test]
    fn an_empty_peer_store_authorizes_nobody() {
        let allow = PeerStoreAllowlist::new(PeerStore::new());
        assert!(!allow.is_authorized(&peer_id(1)));
    }

    #[test]
    fn a_trusted_peer_is_authorized() {
        let store = PeerStore::new();
        trusted(&store, peer_id(1));
        let allow = PeerStoreAllowlist::new(store);
        assert!(allow.is_authorized(&peer_id(1)));
        assert!(
            !allow.is_authorized(&peer_id(2)),
            "trusting one peer must not trust another"
        );
    }

    /// Revocation must take effect for remote execution, not just for display.
    #[test]
    fn a_revoked_peer_is_refused() {
        let store = PeerStore::new();
        trusted(&store, peer_id(3));
        let allow = PeerStoreAllowlist::new(store.clone());
        assert!(allow.is_authorized(&peer_id(3)));

        store.revoke(&peer_id(3)).expect("revoke");
        assert!(
            !allow.is_authorized(&peer_id(3)),
            "a revoked peer must immediately lose the right to submit work"
        );
    }

    #[test]
    fn directory_admits_only_trusted_configured_peers() {
        let store = PeerStore::new();
        let trusted_key = [0xaa; 32];
        let trusted_id = PeerId::from_public_key_bytes(&trusted_key);
        trusted(&store, trusted_id);

        let stranger_key = [0xbb; 32];

        let cfg = SchedulerConfig {
            peers: vec![
                format!("{}@127.0.0.1:4001", hex::encode(trusted_key)),
                // A syntactically fine address for a peer we never paired with.
                format!("{}@127.0.0.1:4002", hex::encode(stranger_key)),
                "not-an-address".to_owned(),
            ],
            ..SchedulerConfig::default()
        };

        let dir = directory_from_config(&cfg, &store, peer_id(9));
        assert_eq!(
            dir.len(),
            1,
            "only the trusted, parseable peer may be dispatched to"
        );
        assert!(dir.lookup(&trusted_id).is_some());
        assert!(
            dir.lookup(&PeerId::from_public_key_bytes(&stranger_key))
                .is_none(),
            "an untrusted peer must not become a dispatch target via config alone"
        );
    }

    #[test]
    fn directory_skips_our_own_address() {
        let store = PeerStore::new();
        let key = [0xcc; 32];
        let me = PeerId::from_public_key_bytes(&key);
        trusted(&store, me);

        let cfg = SchedulerConfig {
            peers: vec![format!("{}@127.0.0.1:4003", hex::encode(key))],
            ..SchedulerConfig::default()
        };
        assert!(directory_from_config(&cfg, &store, me).is_empty());
    }
}
