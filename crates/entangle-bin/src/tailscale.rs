//! Daemon wiring for the `mesh.tailscale` transport (spec §6.1.1).
//!
//! Off unless `[mesh.tailscale] enabled = true` **and** `[mesh] transports`
//! contains `"tailscale"`. When on, the daemon starts the identity-bound TCP
//! listener, the liveness poller, and a discovery task that re-enumerates
//! tailnet peers every 60 s while the tailnet is active. Routing scheduler
//! traffic over this transport is a later step; for now inbound requests get
//! a fixed "no service bound" reply.

use std::sync::Arc;
use std::time::Duration;

use entangle_mesh_tailscale::{
    AclMode, LivenessHandle, MeshTailscale, MeshTailscaleConfig, PeerAllowlist, RequestHandler,
};
use entangle_peers::{PeerStore, TrustLevel};
use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;

use crate::config::MeshConfig;

/// `true` when the daemon should run the `mesh.tailscale` transport.
pub fn enabled(mesh: &MeshConfig) -> bool {
    mesh.tailscale.enabled && mesh.transports.iter().any(|t| t == "tailscale")
}

/// The peer store as the transport's allowlist (fails closed; revoked peers
/// are not allowed).
#[derive(Clone)]
pub struct StoreAllowlist(PeerStore);

impl std::fmt::Debug for StoreAllowlist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreAllowlist")
            .field("trusted_peers", &self.0.len())
            .finish()
    }
}

impl PeerAllowlist for StoreAllowlist {
    fn is_allowed(&self, peer: &PeerId) -> bool {
        matches!(self.0.get(peer), Some(p) if p.trust != TrustLevel::Revoked)
    }
}

struct NoService;

#[async_trait::async_trait]
impl RequestHandler for NoService {
    async fn handle(&self, _peer: PeerId, _payload: Vec<u8>) -> Vec<u8> {
        b"entangle: no service is bound to mesh.tailscale yet".to_vec()
    }
}

/// Running tailscale transport pieces.
pub struct TailscaleRuntime {
    /// The transport.
    pub transport: MeshTailscale,
    /// Liveness poller (dropping it stops polling).
    pub liveness: LivenessHandle,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl TailscaleRuntime {
    /// Stop everything.
    pub async fn shutdown(&self) {
        self.liveness.shutdown();
        self.transport.shutdown().await;
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// Translate daemon config into the transport config.
pub fn build_config(mesh: &MeshConfig, store: PeerStore) -> anyhow::Result<MeshTailscaleConfig> {
    let acl_mode: AclMode = mesh
        .tailscale
        .acl_mode
        .parse()
        .map_err(|e: String| anyhow::anyhow!("[mesh.tailscale] {e}"))?;
    Ok(MeshTailscaleConfig {
        tailscale_cli: mesh.tailscale.tailscale_cli.clone(),
        acl_mode,
        allowlist: Some(Arc::new(StoreAllowlist(store))),
        port: mesh.tailscale.port,
        ..MeshTailscaleConfig::default()
    })
}

/// Start the transport, serving loop, liveness poller and discovery task.
pub async fn start(
    mesh: &MeshConfig,
    identity: &IdentityKeyPair,
    store: PeerStore,
) -> anyhow::Result<TailscaleRuntime> {
    let cfg = build_config(mesh, store)?;
    let liveness = cfg.spawn_liveness();
    let transport = MeshTailscale::start(identity, cfg).await?;
    tracing::info!(
        peer_id = %transport.local_peer_id(),
        addr = %transport.local_addr(),
        "mesh.tailscale transport listening",
    );

    let serve = {
        let t = transport.clone();
        tokio::spawn(async move { t.serve(Arc::new(NoService)).await })
    };
    let discover = {
        let t = transport.clone();
        let mut state = liveness.state();
        let status = liveness.status();
        tokio::spawn(async move {
            loop {
                if state.borrow().is_active() {
                    let snapshot = status.borrow().clone();
                    if let Some(st) = snapshot {
                        let found = t.discover(&st).await;
                        tracing::debug!(candidates = found.len(), "mesh.tailscale discovery round");
                    }
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {}
                    r = state.changed() => if r.is_err() { return },
                }
            }
        })
    };
    Ok(TailscaleRuntime {
        transport,
        liveness,
        tasks: vec![serve, discover],
    })
}
