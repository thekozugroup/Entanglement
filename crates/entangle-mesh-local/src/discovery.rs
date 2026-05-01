//! mDNS service registration and browsing for the `mesh.local` transport.

use crate::{
    errors::DiscoveryError,
    peer::{LocalPeer, PeerSeen},
};
use entangle_types::peer_id::PeerId;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, warn};

/// mDNS-SD service type for Entanglement daemons.
const SERVICE_TYPE: &str = "_entangle._udp.local.";

/// Events emitted by the discovery layer.
#[derive(Clone, Debug)]
pub enum DiscoveryEvent {
    /// A new peer appeared on the network.
    PeerAppeared(PeerSeen),
    /// An already-known peer re-announced (addresses or metadata changed).
    PeerUpdated(PeerSeen),
    /// A peer sent a goodbye or its TTL expired.
    PeerDisappeared {
        /// Identifier of the departing peer.
        peer_id: PeerId,
        /// Last-known display name.
        display_name: String,
    },
}

/// Configuration for [`Discovery`].
#[derive(Clone, Debug)]
pub struct DiscoveryConfig {
    /// Description of the local node to advertise.
    pub local: LocalPeer,
    /// Re-announce interval in seconds. Handled internally by mdns_sd; stored
    /// here for documentation purposes. Default: 30.
    pub announce_interval_secs: u64,
    /// Capacity of the broadcast channel. Default: 256.
    pub channel_capacity: usize,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            local: LocalPeer {
                peer_id: PeerId::from_public_key_bytes(&[0u8; 32]),
                display_name: "entangled".to_string(),
                port: 7700,
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            announce_interval_secs: 30,
            channel_capacity: 256,
        }
    }
}

/// mDNS-based LAN peer discovery handle.
///
/// Create with [`Discovery::new`], then call [`Discovery::start_announcing`]
/// and [`Discovery::spawn_browser`] to begin the discovery loop.
pub struct Discovery {
    daemon: ServiceDaemon,
    sender: broadcast::Sender<DiscoveryEvent>,
    peers: Arc<RwLock<HashMap<PeerId, PeerSeen>>>,
    local: LocalPeer,
    instance_name: String,
}

impl Discovery {
    /// Create a new `Discovery` handle from the given config.
    pub fn new(config: DiscoveryConfig) -> Result<Self, DiscoveryError> {
        let daemon = ServiceDaemon::new().map_err(|e| DiscoveryError::Mdns(e.to_string()))?;
        let (sender, _) = broadcast::channel(config.channel_capacity);
        let peers = Arc::new(RwLock::new(HashMap::new()));

        // Instance name is the peer_id hex — guaranteed unique on the link.
        let instance_name = config.local.peer_id.to_hex();

        Ok(Self {
            daemon,
            sender,
            peers,
            local: config.local,
            instance_name,
        })
    }

    /// Register this node as an mDNS service. Blocks until the registration
    /// command is queued in the daemon.
    pub fn start_announcing(&self) -> Result<(), DiscoveryError> {
        let host_ip = local_ipv4().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let hostname = format!("{}.local.", hostname());
        let txt = self.txt_map();
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            &self.instance_name,
            &hostname,
            host_ip,
            self.local.port,
            txt,
        )
        .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;

        self.daemon
            .register(info)
            .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;
        debug!(peer_id = %self.local.peer_id, port = self.local.port, "mDNS service registered");
        Ok(())
    }

    /// Spawn a Tokio task that consumes the mDNS browse stream and forwards
    /// [`DiscoveryEvent`]s to all broadcast subscribers.
    ///
    /// The returned [`tokio::task::JoinHandle`] runs until the daemon shuts
    /// down or the browse channel closes.
    pub fn spawn_browser(&self) -> Result<tokio::task::JoinHandle<()>, DiscoveryError> {
        let receiver = self
            .daemon
            .browse(SERVICE_TYPE)
            .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;

        let sender = self.sender.clone();
        let peers = self.peers.clone();
        let self_id = self.local.peer_id;

        let handle = tokio::spawn(async move {
            loop {
                match receiver.recv_async().await {
                    Ok(event) => match event {
                        ServiceEvent::ServiceResolved(info) => {
                            if let Some(peer) = parse_service(&info) {
                                if peer.peer_id == self_id {
                                    continue; // skip our own announcement
                                }
                                let mut map = peers.write().await;
                                let evt = if map.contains_key(&peer.peer_id) {
                                    DiscoveryEvent::PeerUpdated(peer.clone())
                                } else {
                                    DiscoveryEvent::PeerAppeared(peer.clone())
                                };
                                map.insert(peer.peer_id, peer);
                                let _ = sender.send(evt);
                            }
                        }
                        ServiceEvent::ServiceRemoved(_, fullname) => {
                            // fullname: "<instance>.<service-type>"; instance == peer_id hex
                            if let Some((instance, _)) = fullname.split_once('.') {
                                if let Ok(peer_id) = PeerId::from_hex(instance) {
                                    let mut map = peers.write().await;
                                    if let Some(p) = map.remove(&peer_id) {
                                        let _ = sender.send(DiscoveryEvent::PeerDisappeared {
                                            peer_id,
                                            display_name: p.display_name,
                                        });
                                    }
                                }
                            }
                        }
                        _ => {} // SearchStarted, ServiceFound — not actionable here
                    },
                    Err(_) => {
                        debug!("mDNS browse channel closed; browser task exiting");
                        break;
                    }
                }
            }
        });

        Ok(handle)
    }

    /// Subscribe to [`DiscoveryEvent`]s. Can be called multiple times for fan-out.
    pub fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent> {
        self.sender.subscribe()
    }

    /// Return a point-in-time snapshot of all currently known remote peers.
    pub async fn snapshot_peers(&self) -> Vec<PeerSeen> {
        self.peers.read().await.values().cloned().collect()
    }

    /// Unregister the mDNS service and shut down the daemon.
    pub fn shutdown(&self) -> Result<(), DiscoveryError> {
        self.daemon
            .shutdown()
            .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;
        Ok(())
    }

    // ── private helpers ──────────────────────────────────────────────────────

    fn txt_map(&self) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("peer_id".into(), self.local.peer_id.to_hex());
        m.insert("display_name".into(), self.local.display_name.clone());
        m.insert("version".into(), self.local.version.clone());
        m
    }
}

// ── free functions ────────────────────────────────────────────────────────────

/// Parse a [`mdns_sd::ResolvedService`] into a [`PeerSeen`], returning `None`
/// if mandatory TXT fields are missing or malformed.
fn parse_service(info: &mdns_sd::ResolvedService) -> Option<PeerSeen> {
    let txt = info.get_properties();
    let peer_id_hex = txt.get_property_val_str("peer_id")?;
    let peer_id = PeerId::from_hex(peer_id_hex)
        .map_err(|e| warn!("bad peer_id in mDNS TXT: {e}"))
        .ok()?;
    let display_name = txt
        .get_property_val_str("display_name")
        .unwrap_or("")
        .to_string();
    let version = txt
        .get_property_val_str("version")
        .unwrap_or("")
        .to_string();

    // Convert ScopedIp → IpAddr (extract address, drop interface scope).
    // ScopedIp is #[non_exhaustive] so we must have a wildcard arm.
    let addresses: Vec<IpAddr> = info
        .get_addresses()
        .iter()
        .filter_map(|s| match s {
            mdns_sd::ScopedIp::V4(v4) => Some(IpAddr::V4(*v4.addr())),
            mdns_sd::ScopedIp::V6(v6) => Some(IpAddr::V6(*v6.addr())),
            _ => None, // forward-compat with future variants
        })
        .collect();

    Some(PeerSeen {
        peer_id,
        display_name,
        addresses,
        port: info.get_port(),
        version,
        last_seen: SystemTime::now(),
    })
}

/// Return the local hostname, preferring the `HOSTNAME`/`HOST` env vars so
/// that the daemon can be configured in containers.
fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "entangled".to_string())
}

/// Best-effort detection of the primary outbound IPv4 address by probing a
/// UDP connect (no packets are sent).
fn local_ipv4() -> Option<IpAddr> {
    use std::net::UdpSocket;
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?;
    s.local_addr().ok().map(|a| a.ip())
}
