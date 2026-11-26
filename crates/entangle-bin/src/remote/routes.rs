//! Scheduler routes from configured long addresses and Tailscale status.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use anyhow::{ensure, Context};
use entangle_mesh_iroh::{IrohPeer, MeshIroh};
use entangle_mesh_local::{Discovery, PeerSeen};
use entangle_mesh_tailscale::{MeshTailscale, TailnetStatus};
use entangle_peers::PeerStore;
use entangle_scheduler::{PeerAddressBook, PeerAllowlist};
use entangle_signing::{IdentityKeyPair, IdentityPublicKey};
use entangle_types::peer_id::PeerId;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::config::{Config, TailnetPeerConfig};

use super::{
    bind_scheduler, configured_peers, parse_bind, scheduler_transport_enabled, PeerStoreAllowlist,
};

const REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const BIND_TIMEOUT: Duration = Duration::from_secs(15);

/// A bound scheduler endpoint and the address book for its dispatcher.
pub struct PreparedScheduler {
    /// Authenticated scheduler endpoint shared by the client and server.
    pub transport: Arc<MeshIroh>,
    /// Looks up configured addresses and checks current trust at dispatch time.
    pub addresses: Arc<dyn PeerAddressBook>,
    /// LAN routes when both mDNS discovery and Iroh dispatch are enabled.
    pub lan: Option<Arc<LanRoutes>>,
    /// Configured, non-local Entanglement IDs for capability polling.
    pub peer_ids: Vec<PeerId>,
    /// Transport names currently available, refreshed with the tailnet routes.
    pub active_transports: watch::Receiver<Vec<String>>,
    refresh: Option<JoinHandle<()>>,
}

impl Drop for PreparedScheduler {
    fn drop(&mut self) {
        if let Some(task) = self.refresh.take() {
            task.abort();
        }
    }
}

/// LAN reachability hints from the discovery layer's current mDNS cache.
pub struct LanRoutes {
    discovery: OnceLock<Arc<Discovery>>,
    bind: SocketAddr,
    local_id: PeerId,
    store: PeerStore,
}

impl std::fmt::Debug for LanRoutes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LanRoutes")
            .field("bind", &self.bind)
            .finish_non_exhaustive()
    }
}

impl LanRoutes {
    /// Attach the daemon's browser once it has started.
    pub fn attach(&self, discovery: Arc<Discovery>) {
        let _ = self.discovery.set(discovery);
    }

    fn lookup(&self, id: &PeerId) -> Option<IrohPeer> {
        if id == &self.local_id {
            return None;
        }
        let seen = self.discovery.get()?.lookup_peer(id)?;
        lan_peer(&seen, self.bind)
    }

    /// Enumerate only operator-trusted, dialable nodes. Reads the current
    /// trust store once per poll on the caller's blocking worker.
    pub fn peer_ids(&self) -> Vec<PeerId> {
        if self.discovery.get().is_none() {
            return Vec::new();
        }
        self.store
            .list_current()
            .unwrap_or_default()
            .into_iter()
            .filter(|p| {
                p.trust == entangle_peers::TrustLevel::Trusted && self.lookup(&p.peer_id).is_some()
            })
            .map(|p| p.peer_id)
            .collect()
    }
}

fn lan_peer(seen: &PeerSeen, bind: SocketAddr) -> Option<IrohPeer> {
    let key = seen.public_key?;
    let port = seen.mesh_port.filter(|p| *p != 0)?;
    if PeerId::from_public_key_bytes(&key) != seen.peer_id {
        return None;
    }
    let mut targets = seen
        .addresses
        .iter()
        .copied()
        .filter(|ip| {
            ip.is_ipv4() == bind.is_ipv4()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_loopback()
                && match ip {
                    IpAddr::V4(ip) => !ip.is_broadcast(),
                    // A link-local IPv6 destination requires an interface scope,
                    // which the portable PeerSeen address list does not carry.
                    IpAddr::V6(ip) => !ip.is_unicast_link_local() && ip.to_ipv4_mapped().is_none(),
                }
        })
        .take(16)
        .map(|ip| SocketAddr::new(ip, port));
    let peer = IrohPeer::new(key, targets.next()?);
    Some(targets.fold(peer, IrohPeer::with_addr))
}

#[derive(Debug)]
struct SchedulerAddresses {
    lan: Option<Arc<LanRoutes>>,
    static_peers: HashMap<PeerId, IrohPeer>,
    // Swap whole snapshots so disappeared, offline and readdressed nodes
    // immediately lose their old hints after refresh.
    tailnet: RwLock<HashMap<PeerId, IrohPeer>>,
    trust: PeerStoreAllowlist,
}

impl PeerAddressBook for SchedulerAddresses {
    fn lookup(&self, id: &PeerId) -> Option<IrohPeer> {
        let static_peer = self.static_peers.get(id).cloned();
        let tailnet = self
            .tailnet
            .read()
            .ok()
            .and_then(|routes| routes.get(id).cloned());
        let lan = self.lan.as_ref().and_then(|routes| routes.lookup(id));
        let mut sources = [static_peer, tailnet, lan].into_iter().flatten();
        let first = sources.next()?;
        let peer = sources.fold(first, |peer, extra| {
            extra.addrs().fold(peer, IrohPeer::with_addr)
        });
        self.trust.is_authorized(id).then_some(peer)
    }
}

#[derive(Debug)]
struct Mapping {
    node_id: String,
    public_key: [u8; 32],
    port: u16,
}

impl Mapping {
    fn parse(cfg: &TailnetPeerConfig) -> anyhow::Result<Self> {
        ensure!(!cfg.node_id.trim().is_empty(), "empty Tailscale node ID");
        let mut public_key = [0; 32];
        hex::decode_to_slice(&cfg.public_key, &mut public_key)
            .context("expected a 64-digit Entanglement public key")?;
        IdentityPublicKey::from_bytes(&public_key).context("invalid Entanglement public key")?;
        Ok(Self {
            node_id: cfg.node_id.clone(),
            public_key,
            port: cfg.port.get(),
        })
    }
}

// Accept only Tailscale's node-address space, including for the local bind.
// Subnet routes, LAN addresses and exit-node routes do not designate nodes.
fn is_tailnet_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            a == 100 && (64..128).contains(&b)
        }
        IpAddr::V6(v6) => v6.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
    }
}

fn tailnet_bind(requested: SocketAddr, status: &TailnetStatus) -> anyhow::Result<SocketAddr> {
    let ip = status
        .local_ips
        .iter()
        .copied()
        .find(|ip| {
            is_tailnet_ip(*ip)
                && ip.is_ipv4() == requested.is_ipv4()
                && (requested.ip().is_unspecified() || *ip == requested.ip())
        })
        .context(
            "scheduler bind requires a local Tailscale address in the requested address family",
        )?;
    Ok(SocketAddr::new(ip, requested.port()))
}

async fn online_status(
    mesh: &MeshTailscale,
    bind: SocketAddr,
) -> anyhow::Result<(TailnetStatus, SocketAddr)> {
    let status = mesh.status().await?;
    ensure!(
        status.is_running(),
        "Tailscale node offline (backend {})",
        status.backend_state
    );
    let local = tailnet_bind(bind, &status)?;
    Ok((status, local))
}

fn snapshot_routes(
    status: &TailnetStatus,
    mappings: &[Mapping],
    bind: SocketAddr,
) -> HashMap<PeerId, IrohPeer> {
    let mut routes = HashMap::new();
    if mappings.is_empty() || !status.is_running() {
        return routes;
    }
    let online: HashMap<_, _> = status
        .peers
        .iter()
        .filter(|node| node.online)
        .map(|node| (node.node_id.as_str(), node))
        .collect();
    for mapping in mappings {
        let Some(node) = online.get(mapping.node_id.as_str()) else {
            continue;
        };
        let Some(ip) = node
            .ips
            .iter()
            .copied()
            .find(|ip| ip.is_ipv4() == bind.is_ipv4() && is_tailnet_ip(*ip))
        else {
            continue;
        };
        let addr = SocketAddr::new(ip, mapping.port);
        let id = PeerId::from_public_key_bytes(&mapping.public_key);
        let peer = match routes.remove(&id) {
            Some(peer) => peer.with_addr(addr),
            None => IrohPeer::new(mapping.public_key, addr),
        };
        routes.insert(id, peer);
    }
    routes
}

/// Prepare the enabled scheduler routes. A Tailscale-only endpoint binds to
/// this machine's tailnet IP with relay disabled. Mixed mode retains the
/// operator's ordinary Iroh bind and can run while Tailscale is unavailable.
///
/// A Tailscale status snapshot may supply IPs only for explicitly mapped
/// stable node IDs. QUIC still authenticates the configured Entanglement key.
pub async fn prepare_scheduler(
    cfg: &Config,
    identity: &IdentityKeyPair,
    store: &PeerStore,
    local_peer_id: PeerId,
) -> anyhow::Result<Option<PreparedScheduler>> {
    prepare_with_discovery(
        cfg,
        identity,
        store,
        local_peer_id,
        MeshTailscale::default(),
        REFRESH_INTERVAL,
    )
    .await
}

async fn prepare_with_discovery(
    cfg: &Config,
    identity: &IdentityKeyPair,
    store: &PeerStore,
    local_peer_id: PeerId,
    mesh: MeshTailscale,
    refresh_interval: Duration,
) -> anyhow::Result<Option<PreparedScheduler>> {
    if !scheduler_transport_enabled(&cfg.mesh.transports) {
        return Ok(None);
    }

    let iroh = cfg.mesh.transports.iter().any(|t| t == "iroh");
    let tailscale = cfg.mesh.transports.iter().any(|t| t == "tailscale");
    let mut active_transports = Vec::new();
    let mut bind = parse_bind(&cfg.scheduler)?;
    let mut peer_ids = BTreeSet::new();
    let mut static_peers = HashMap::new();
    if iroh {
        active_transports.push("iroh".to_owned());
        for peer in configured_peers(&cfg.scheduler, local_peer_id) {
            peer_ids.insert(peer.peer_id);
            static_peers.insert(peer.peer_id, peer);
        }
    }

    let mut previous_error = None;
    let mut mappings = Vec::new();
    let mut tailnet = HashMap::new();
    if tailscale {
        for cfg in &cfg.scheduler.tailnet_peers {
            match Mapping::parse(cfg) {
                Ok(mapping) => {
                    let id = PeerId::from_public_key_bytes(&mapping.public_key);
                    if id != local_peer_id {
                        peer_ids.insert(id);
                        mappings.push(mapping);
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "[scheduler] skipping invalid tailnet_peers mapping")
                }
            }
        }
        match online_status(&mesh, bind).await {
            Ok((status, local)) => {
                if !iroh {
                    bind = local;
                }
                active_transports.push("tailscale".to_owned());
                tailnet = snapshot_routes(&status, &mappings, bind);
            }
            Err(e) if iroh => {
                tracing::warn!(error = %e, "Tailscale unavailable, continuing with Iroh");
                previous_error = Some(e.to_string());
            }
            Err(e) => return Err(e),
        }
    }

    let transport = tokio::time::timeout(
        BIND_TIMEOUT,
        bind_scheduler(bind, iroh && cfg.scheduler.relay, identity),
    )
    .await
    .with_context(|| format!("scheduler endpoint timed out binding {bind}"))??;
    let lan = (iroh && cfg.mesh.transports.iter().any(|t| t == "local")).then(|| {
        Arc::new(LanRoutes {
            discovery: OnceLock::new(),
            bind,
            local_id: local_peer_id,
            store: store.clone(),
        })
    });
    let addresses = Arc::new(SchedulerAddresses {
        lan: lan.clone(),
        static_peers,
        tailnet: RwLock::new(tailnet),
        trust: PeerStoreAllowlist::new(store.clone()),
    });
    let (active_tx, active_transports) = watch::channel(active_transports);
    let refresh = tailscale.then(|| {
        let addresses = addresses.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(refresh_interval).await;
                let (updated, error) = match online_status(&mesh, bind).await {
                    Ok((status, _)) => (snapshot_routes(&status, &mappings, bind), None),
                    Err(e) => (HashMap::new(), Some(e.to_string())),
                };
                if let Ok(mut routes) = addresses.tailnet.write() {
                    *routes = updated;
                }
                if previous_error != error {
                    match &error {
                        Some(error) => {
                            tracing::warn!(%error, "Tailscale scheduler routes unavailable")
                        }
                        None => tracing::info!("Tailscale scheduler routes available"),
                    }
                    if previous_error.is_some() != error.is_some() {
                        active_tx.send_modify(|names| {
                            if error.is_some() {
                                names.retain(|name| name != "tailscale");
                            } else {
                                names.push("tailscale".to_owned());
                            }
                        });
                    }
                    previous_error = error;
                }
            }
        })
    });
    Ok(Some(PreparedScheduler {
        lan,
        transport,
        addresses,
        peer_ids: peer_ids.into_iter().collect(),
        active_transports,
        refresh,
    }))
}

#[cfg(test)]
mod tests;
