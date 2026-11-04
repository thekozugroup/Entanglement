//! Daemon wiring for multi-transport scheduling (spec §6.1, §6.1.1).
//!
//! The daemon serves and dispatches the scheduler protocols over every
//! transport it runs:
//!
//! * **inbound** — one [`RemoteTaskServer`] and one [`StreamServer`]
//!   ([`scheduler_servers`]) behind the peer-store allowlist, served on the
//!   iroh endpoint (per ALPN) and on the tailnet listener (per selected
//!   sub-protocol), so in-flight tables and stream limits span transports;
//! * **outbound** — a [`TransportRouter`](entangle_scheduler::TransportRouter) ([`build_router`]) with a link
//!   per transport: `local` (mDNS sightings dialled over the iroh endpoint),
//!   `tailscale` (tailnet discovery candidates, while the tailnet is
//!   active) and `iroh` (`[scheduler] peers`), ordered by `[mesh]
//!   preferred` / `[mesh.overrides]`.
//!
//! mDNS sightings become `local` dial targets only for trusted,
//! non-revoked peers that advertise their key and mesh port
//! ([`track_sighting`]); the QUIC handshake then authenticates the key, so
//! a spoofed sighting can at worst point at an address that fails to
//! authenticate.

use std::sync::Arc;

use entangle_mesh_iroh::{IrohPeer, MeshIroh};
use entangle_mesh_local::{DiscoveryEvent, PeerSeen};
use entangle_peers::{PeerStore, TrustLevel};
use entangle_runtime::Kernel;
use entangle_scheduler::{PeerDirectory, RemoteTaskServer, StreamServer, TransportKind};
use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;

use crate::config::MeshConfig;
use crate::remote::PeerStoreAllowlist;

/// The servers every transport hands inbound scheduler traffic to.
#[derive(Clone, Debug)]
pub struct SchedulerServers {
    /// One-shot tasks (`entangle/scheduler/1`).
    pub tasks: Arc<RemoteTaskServer>,
    /// Streaming tasks (`entangle/stream/1`).
    pub streams: Arc<StreamServer>,
}

/// Build the task and stream servers, both gated on `store` (see
/// [`PeerStoreAllowlist`]). Chunks are signed with `identity`, which must be
/// the transports' identity.
pub fn scheduler_servers(
    kernel: Arc<Kernel>,
    store: PeerStore,
    identity: IdentityKeyPair,
    metrics: Option<entangle_observability::Registry>,
) -> SchedulerServers {
    let allowlist = Arc::new(PeerStoreAllowlist::new(store));
    let local = PeerId::from_public_key_bytes(identity.public().as_bytes());
    let mut tasks = RemoteTaskServer::new(Arc::clone(&kernel), allowlist.clone(), local);
    if let Some(registry) = metrics {
        tasks = tasks.with_metrics(registry);
    }
    tracing::info!(trusted_peers = ?allowlist, "serving scheduler tasks and streams for trusted peers");
    SchedulerServers {
        tasks: Arc::new(tasks),
        streams: Arc::new(StreamServer::new(kernel, allowlist, identity)),
    }
}

/// Serve `servers` on the iroh scheduler endpoint: `entangle/scheduler/1`
/// and `entangle/stream/1` on the same socket. Returns the accept loops.
pub fn serve_on_iroh(
    transport: &Arc<MeshIroh>,
    servers: &SchedulerServers,
) -> Vec<tokio::task::JoinHandle<()>> {
    vec![
        tokio::spawn(entangle_scheduler::serve_tasks(
            Arc::clone(transport),
            Arc::clone(&servers.tasks),
        )),
        tokio::spawn(entangle_scheduler::serve_streams(
            Arc::clone(transport),
            Arc::clone(&servers.streams),
        )),
    ]
}

fn trusted(store: &PeerStore, peer: &PeerId) -> bool {
    matches!(store.get(peer), Some(p) if p.trust != TrustLevel::Revoked)
}

/// The `mesh.local` dial target an mDNS sighting gives: its advertised key
/// and every resolved address on its advertised mesh port. `None` when the
/// sighting carries no key or no address.
pub fn sighting_route(seen: &PeerSeen) -> Option<IrohPeer> {
    let key = seen.public_key?;
    let mut addrs = seen.dial_targets().into_iter();
    let first = addrs.next()?;
    Some(addrs.fold(IrohPeer::new(key, first), IrohPeer::with_addr))
}

/// Keep `sightings` — the `local` link's address book — in step with one
/// discovery event: trusted, non-revoked, dialable peers other than this
/// node are (re)inserted; anything else, and a peer that disappeared, is
/// removed.
pub fn track_sighting(
    sightings: &PeerDirectory,
    event: &DiscoveryEvent,
    store: &PeerStore,
    local: PeerId,
) {
    match event {
        DiscoveryEvent::PeerAppeared(p) | DiscoveryEvent::PeerUpdated(p) => {
            match sighting_route(p) {
                Some(route) if p.peer_id != local && trusted(store, &p.peer_id) => {
                    sightings.insert(route);
                }
                _ => {
                    sightings.remove(&p.peer_id);
                }
            }
        }
        DiscoveryEvent::PeerDisappeared { peer_id, .. } => {
            sightings.remove(peer_id);
        }
    }
}

/// Rebuild `sightings` from a discovery snapshot (after the event stream
/// lagged).
pub fn resync_sightings(
    sightings: &PeerDirectory,
    snapshot: &[PeerSeen],
    store: &PeerStore,
    local: PeerId,
) {
    for peer in sightings.peers() {
        if !snapshot.iter().any(|p| p.peer_id == peer) {
            sightings.remove(&peer);
        }
    }
    for seen in snapshot {
        track_sighting(
            sightings,
            &DiscoveryEvent::PeerUpdated(seen.clone()),
            store,
            local,
        );
    }
}

/// The router inputs and builder live in the scheduler library, shared with
/// `entangle compute stream`, so the daemon and the CLI pick transports the
/// same way.
pub use entangle_scheduler::transport::{build_router, RouterInputs};

/// Warn about `[mesh] preferred` / `[mesh.overrides]` entries naming a
/// transport this node is not running: they are kept (the transport may be
/// enabled later) but cannot carry anything now.
pub fn warn_unavailable_choices(mesh: &MeshConfig, running: &[TransportKind]) {
    let off = |name: &str| {
        name.parse::<TransportKind>()
            .is_ok_and(|k| !running.contains(&k))
    };
    if let Some(p) = mesh.preferred.as_deref().filter(|p| off(p)) {
        tracing::warn!(
            preferred = p,
            running = ?running.iter().map(|k| k.as_str()).collect::<Vec<_>>(),
            "[mesh] preferred names a transport that is not running; the others are used"
        );
    }
    for (peer, choice) in &mesh.overrides {
        let names = choice.names();
        if names.iter().all(|n| off(n)) {
            tracing::warn!(
                %peer,
                transports = ?names,
                "[mesh.overrides]: none of this peer's transports is running, so it is unreachable"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use entangle_peers::TrustedPeer;
    use entangle_scheduler::PeerAddressBook;
    use std::net::{IpAddr, Ipv4Addr};

    fn seen(key: [u8; 32], with_key: bool) -> PeerSeen {
        PeerSeen {
            peer_id: PeerId::from_public_key_bytes(&key),
            display_name: "desk".into(),
            addresses: vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 31)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 31)),
            ],
            port: 7001,
            version: "0".into(),
            hardware: None,
            public_key: with_key.then_some(key),
            mesh_port: Some(41641),
            last_seen: std::time::SystemTime::now(),
        }
    }

    #[test]
    fn only_trusted_dialable_sightings_become_local_routes() {
        let store = PeerStore::new();
        let (trusted_key, stranger_key, keyless) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        for key in [trusted_key, keyless] {
            store
                .add(TrustedPeer::new(
                    PeerId::from_public_key_bytes(&key),
                    hex::encode(key),
                    "x".into(),
                ))
                .unwrap();
        }
        let dir = PeerDirectory::new();
        let me = PeerId::from_public_key_bytes(&[9; 32]);
        for p in [
            seen(trusted_key, true),
            seen(stranger_key, true),
            seen(keyless, false),
        ] {
            track_sighting(&dir, &DiscoveryEvent::PeerAppeared(p), &store, me);
        }
        assert_eq!(dir.len(), 1, "only the trusted sighting with a key");
        let route = dir
            .lookup(&PeerId::from_public_key_bytes(&trusted_key))
            .unwrap();
        assert_eq!(route.public_key, trusted_key);
        assert_eq!(route.addr.to_string(), "192.168.1.31:41641");
        assert_eq!(
            route.extra_addrs.len(),
            1,
            "every resolved address is a hint"
        );

        // Revocation and disappearance remove the route.
        store
            .revoke(&PeerId::from_public_key_bytes(&trusted_key))
            .unwrap();
        track_sighting(
            &dir,
            &DiscoveryEvent::PeerUpdated(seen(trusted_key, true)),
            &store,
            me,
        );
        assert!(dir.is_empty());
        let resync_store = PeerStore::new();
        resync_store
            .add(TrustedPeer::new(
                PeerId::from_public_key_bytes(&stranger_key),
                hex::encode(stranger_key),
                "y".into(),
            ))
            .unwrap();
        resync_sightings(&dir, &[seen(stranger_key, true)], &resync_store, me);
        assert_eq!(dir.peers(), [PeerId::from_public_key_bytes(&stranger_key)]);
        resync_sightings(&dir, &[], &resync_store, me);
        assert!(dir.is_empty());
    }

    #[test]
    fn no_running_transport_means_no_router() {
        assert!(build_router(
            PeerId::from_public_key_bytes(&[1; 32]),
            RouterInputs::default()
        )
        .is_none());
    }
}
