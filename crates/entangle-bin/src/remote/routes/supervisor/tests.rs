use super::*;
use entangle_mesh_iroh::serve;
use entangle_mesh_tailscale::MeshTailscaleConfig;
use entangle_runtime::{Kernel, KernelConfig};
use entangle_signing::Keyring;
use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test]
async fn outbound_handle_uses_the_new_generation_without_resubmitting_jobs() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let identity = IdentityKeyPair::generate();
        let endpoint = bind_scheduler(local, false, &identity).await.unwrap();
        let bound = endpoint.local_addrs()[0];
        let stable = TailnetTransport::new(&identity);
        assert!(stable.publish(endpoint));
        let worker = bind_scheduler(local, false, &IdentityKeyPair::generate())
            .await
            .unwrap();
        let peer = IrohPeer::new(worker.local_public_key(), worker.local_addrs()[0]);
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let id = stable.local_peer_id();
        let echo = tokio::spawn(serve(worker.clone(), move |caller, data| {
            assert_eq!(caller, id);
            count.fetch_add(1, Ordering::SeqCst);
            async move { data }
        }));
        assert_eq!(stable.request(&peer, b"first").await.unwrap(), b"first");
        TailnetTransport::close(stable.withdraw(EndpointState::Recovering)).await;
        assert!(stable.local_addrs().is_empty());
        assert!(stable.request(&peer, b"while offline").await.is_err());
        let next = bind_scheduler(bound, false, &identity).await.unwrap();
        assert!(stable.publish(next));
        assert_eq!(stable.local_addrs(), [bound]);
        assert_eq!(stable.request(&peer, b"second").await.unwrap(), b"second");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        stable.shutdown().await;
        let late = bind_scheduler(bound, false, &identity).await.unwrap();
        assert!(!stable.publish(late));
        assert!(stable.accept().await.unwrap().is_none());
        worker.shutdown().await;
        echo.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn terminal_accept_withdraws_service_and_shutdown_interrupts_recovery() {
    check_service_shutdown(true).await;
}

#[tokio::test]
async fn planned_shutdown_stops_the_active_listener_permanently() {
    check_service_shutdown(false).await;
}

async fn check_service_shutdown(terminal: bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        let identity = IdentityKeyPair::generate();
        let endpoint = bind_scheduler("127.0.0.1:0".parse().unwrap(), false, &identity)
            .await
            .unwrap();
        let port = endpoint.local_addrs()[0].port();
        let transport = Arc::new(TailnetTransport::new(&identity));
        assert!(transport.publish(endpoint.clone()));
        let store = PeerStore::new();
        let addresses = Arc::new(SchedulerAddresses {
            static_peers: HashMap::new(),
            tailnet: RwLock::new(HashMap::new()),
            lan: None,
            trust: PeerStoreAllowlist::new(store.clone()),
        });
        let addr = IrohPeer::new(
            *IdentityKeyPair::generate().public().as_bytes(),
            "100.64.0.9:4444".parse::<SocketAddr>().unwrap(),
        );
        addresses
            .tailnet
            .write()
            .unwrap()
            .insert(addr.peer_id, addr);
        let (active, mut reported) = watch::channel(vec!["tailscale".into()]);
        let supervisor = TailnetSupervisor {
            transport: transport.clone(),
            identity,
            requested: SocketAddr::new("100.64.0.2".parse().unwrap(), port),
            mesh: MeshTailscale::new(MeshTailscaleConfig {
                tailscale_cli: "/nonexistent/entangle-supervisor-test".into(),
                ..Default::default()
            }),
            mappings: vec![],
            addresses: addresses.clone(),
            active,
            refresh_interval: Duration::from_secs(60),
        };
        let server = Arc::new(RemoteTaskServer::new(
            Arc::new(Kernel::new(KernelConfig::default(), Keyring::new()).unwrap()),
            Arc::new(PeerStoreAllowlist::new(store)),
            transport.local_peer_id(),
        ));
        let service = tokio::spawn(supervisor.run(server));
        // Simulate the old driver's terminal accept result, independently of Tailscale polling.
        if terminal {
            endpoint.shutdown().await;
        } else {
            transport.shutdown().await;
        }
        reported.wait_for(Vec::is_empty).await.unwrap();
        assert!(addresses.tailnet.read().unwrap().is_empty());
        assert!(transport.local_addrs().is_empty());
        // This cancellation must not wait for the backoff or the next status refresh.
        transport.shutdown().await;
        tokio::time::timeout(Duration::from_secs(2), service)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(*transport.state.borrow(), EndpointState::Stopped));
    })
    .await
    .unwrap();
}

#[test]
fn first_ephemeral_port_is_pinned_to_one_verified_socket() {
    let actual: SocketAddr = "100.64.1.2:48912".parse().unwrap();
    let ephemeral = SocketAddr::new(actual.ip(), 0);
    let mut requested: SocketAddr = "0.0.0.0:0".parse().unwrap();
    requested.set_port(bound_port(ephemeral, &[actual]).unwrap());
    assert_eq!(requested.port(), 48912);
    assert_eq!(bound_port(actual, &[actual]).unwrap(), requested.port());
    for invalid in [
        vec![],
        vec![ephemeral],
        vec!["0.0.0.0:48912".parse().unwrap()],
        vec!["100.64.1.3:48912".parse().unwrap()],
        vec![actual, "127.0.0.1:48912".parse().unwrap()],
        vec!["100.64.1.2:48913".parse().unwrap()],
    ] {
        assert!(bound_port(actual, &invalid).is_err());
    }
}
