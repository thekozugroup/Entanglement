use super::*;
use entangle_mesh_tailscale::TailnetNode;
use entangle_peers::{TrustLevel, TrustedPeer};

#[tokio::test]
async fn static_routes_keep_the_working_hint_when_the_last_address_is_unreachable() {
    use entangle_mesh_iroh::{format_node_addr, serve, MeshTransport};

    tokio::time::timeout(Duration::from_secs(10), async {
        let bind = "127.0.0.1:0".parse().unwrap();
        let worker = bind_scheduler(bind, false, &IdentityKeyPair::generate())
            .await
            .unwrap();
        let key = worker.local_public_key();
        let id = worker.local_peer_id();
        let live = worker.local_addrs()[0];
        let idle = std::net::UdpSocket::bind(bind).unwrap();
        let stale = idle.local_addr().unwrap();
        let server = tokio::spawn(serve(worker.clone(), |_, data| async move { data }));

        let coordinator = IdentityKeyPair::generate();
        let local = PeerId::from_public_key_bytes(coordinator.public().as_bytes());
        let store = PeerStore::new();
        store
            .add(TrustedPeer::new(id, hex::encode(key), "worker".into()))
            .unwrap();
        let mut config = Config::default();
        config.mesh.transports = vec!["iroh".into()];
        config.scheduler.bind = bind.to_string();
        config.scheduler.relay = false;
        config.scheduler.peers = [live, live, stale]
            .map(|addr| format_node_addr(&key, addr))
            .into();
        let prepared = prepare_scheduler(&config, &coordinator, &store, local)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(prepared.peer_ids, [id]);
        let peer = prepared.addresses.lookup(&id).unwrap();
        assert_eq!(peer.addrs().collect::<Vec<_>>(), [live, stale]);
        assert_eq!(
            prepared
                .transport
                .request(&peer, b"reachable")
                .await
                .unwrap(),
            b"reachable"
        );
        prepared.transport.shutdown().await;
        worker.shutdown().await;
        server.await.unwrap();
    })
    .await
    .expect("configured hints must reach the live worker");
}

fn node(id: &str, online: bool, ips: &[&str]) -> TailnetNode {
    TailnetNode {
        node_id: id.to_owned(),
        hostname: "same-name".into(),
        magic_dns: "same-name.example.ts.net".into(),
        online,
        ips: ips.iter().map(|ip| ip.parse().unwrap()).collect(),
    }
}

fn status() -> TailnetStatus {
    TailnetStatus {
        backend_state: "Running".into(),
        local_online: true,
        local_ips: vec![
            "100.101.2.3".parse().unwrap(),
            "fd7a:115c:a1e0::1".parse().unwrap(),
        ],
        dns_suffix: String::new(),
        peers: vec![
            node(
                "worker",
                true,
                &["192.0.2.9", "fd7a:115c:a1e0::2", "100.64.22.9"],
            ),
            node("outsider", true, &["100.64.0.11"]),
        ],
    }
}

#[test]
fn tailnet_only_bind_keeps_family_and_port_and_requires_local_node_ip() {
    let status = status();
    for (requested, expected) in [
        ("0.0.0.0:7300", "100.101.2.3:7300"),
        ("[::]:7777", "[fd7a:115c:a1e0::1]:7777"),
        ("100.101.2.3:0", "100.101.2.3:0"),
    ] {
        assert_eq!(
            tailnet_bind(requested.parse().unwrap(), &status).unwrap(),
            expected.parse::<SocketAddr>().unwrap()
        );
    }
    for ip in ["127.0.0.1:0", "100.101.2.4:0", "[::1]:7300"] {
        assert!(tailnet_bind(ip.parse().unwrap(), &status).is_err());
    }
    let mut spoofed = status;
    spoofed.local_ips = vec!["0.0.0.0".parse().unwrap(), "192.168.1.1".parse().unwrap()];
    assert!(tailnet_bind("0.0.0.0:0".parse().unwrap(), &spoofed).is_err());
}

#[test]
fn snapshots_follow_only_mapped_online_nodes_and_current_trust() {
    let key = *IdentityKeyPair::generate().public().as_bytes();
    let id = PeerId::from_public_key_bytes(&key);
    let mappings = [Mapping {
        node_id: "worker".into(),
        public_key: key,
        port: 7300,
    }];
    let store = PeerStore::new();
    let addresses = SchedulerAddresses {
        lan: None,
        static_peers: HashMap::new(),
        tailnet: RwLock::new(HashMap::new()),
        tailnet_demand: None,
        trust: PeerStoreAllowlist::new(store.clone()),
    };
    let mut status = status();
    status.peers[0].ips.extend([
        "100.64.22.10".parse::<IpAddr>().unwrap(),
        "100.64.22.9".parse().unwrap(),
    ]);
    let update = |status: &TailnetStatus| {
        *addresses.tailnet.write().unwrap() =
            snapshot_routes(status, &mappings, "0.0.0.0:0".parse().unwrap());
    };
    update(&status);
    assert!(addresses.lookup(&id).is_none(), "a mapping grants no trust");
    let mut peer = TrustedPeer::new(id, hex::encode(key), "remote".into());
    peer.trust = TrustLevel::Observer;
    store.add(peer.clone()).unwrap();
    assert!(addresses.lookup(&id).is_none());
    peer.trust = TrustLevel::Trusted;
    store.add(peer).unwrap();
    let dial = addresses.lookup(&id).unwrap();
    assert_eq!(dial.public_key, key);
    assert_eq!(
        dial.addrs().collect::<Vec<_>>(),
        [
            "100.64.22.9:7300".parse().unwrap(),
            "100.64.22.10:7300".parse().unwrap(),
        ]
    );

    status.peers[0].online = false;
    update(&status);
    assert!(
        addresses.lookup(&id).is_none(),
        "a different online node has the same DNS name"
    );
    status.peers[0].online = true;
    status.peers[0].ips = vec!["100.64.33.8".parse().unwrap()];
    update(&status);
    let dial = addresses.lookup(&id).unwrap();
    assert_eq!(
        dial.addrs().collect::<Vec<_>>(),
        vec!["100.64.33.8:7300".parse::<SocketAddr>().unwrap()]
    );
    store.revoke(&id).unwrap();
    assert!(
        addresses.lookup(&id).is_none(),
        "revocation applied before the next refresh"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn offline_start_preserves_identity_without_a_listener_and_other_modes_keep_working() {
    use entangle_mesh_tailscale::MeshTailscaleConfig;

    let dir = tempfile::tempdir().unwrap();
    let missing_cli = || {
        MeshTailscale::new(MeshTailscaleConfig {
            tailscale_cli: dir.path().join("missing").display().to_string(),
            ..Default::default()
        })
    };
    let identity = IdentityKeyPair::generate();
    let local = PeerId::from_public_key_bytes(identity.public().as_bytes());
    let store = PeerStore::new();
    let mut cfg = Config::default();
    cfg.scheduler.bind = "127.0.0.1:0".into();
    cfg.scheduler.relay = false;

    for transports in [
        vec![],
        vec!["tailscale"],
        vec!["iroh"],
        vec!["iroh", "tailscale"],
    ] {
        cfg.mesh.transports = transports.iter().copied().map(str::to_owned).collect();
        if transports == ["tailscale"] {
            cfg.scheduler.bind = "0.0.0.0:0".into();
        } else {
            cfg.scheduler.bind = "127.0.0.1:0".into();
        }
        let result = prepare_with_discovery(
            &cfg,
            &identity,
            &store,
            local,
            missing_cli(),
            REFRESH_INTERVAL,
        )
        .await;
        if transports.is_empty() {
            assert!(result.unwrap().is_none());
        } else if transports == ["tailscale"] {
            let mut mesh = result.unwrap().unwrap();
            assert!(mesh.active_transports.borrow().is_empty());
            assert!(mesh.transport.local_addrs().is_empty());
            assert_eq!(mesh.transport.local_peer_id(), local);
            assert_eq!(
                mesh.transport.local_public_key(),
                *identity.public().as_bytes()
            );
            let remote = IrohPeer::new(
                *IdentityKeyPair::generate().public().as_bytes(),
                "100.64.0.9:7443".parse::<SocketAddr>().unwrap(),
            );
            assert!(mesh.transport.connect(&remote).await.is_err());
            let server = Arc::new(RemoteTaskServer::new(
                Arc::new(
                    entangle_runtime::Kernel::new(
                        entangle_runtime::KernelConfig::default(),
                        entangle_signing::Keyring::new(),
                    )
                    .unwrap(),
                ),
                Arc::new(PeerStoreAllowlist::new(store.clone())),
                local,
            ));
            mesh.serve(server).unwrap();
            tokio::time::timeout(Duration::from_secs(2), mesh.shutdown())
                .await
                .unwrap();
            cfg.scheduler.bind = "127.0.0.1:7443".into();
            assert!(prepare_with_discovery(
                &cfg,
                &identity,
                &store,
                local,
                missing_cli(),
                REFRESH_INTERVAL
            )
            .await
            .is_err());
        } else {
            let mesh = result.unwrap().unwrap();
            assert_eq!(&*mesh.active_transports.borrow(), &["iroh"]);
            mesh.transport.shutdown().await;
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn mixed_listener_reloads_routes_and_status_from_the_local_cli() {
    use entangle_mesh_tailscale::MeshTailscaleConfig;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    let dir = tempfile::tempdir().unwrap();
    let executable = dir.path().join("tailscale");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../entangle-mesh-tailscale/tests/fixtures/status-cli.sh");
    symlink(fixture, &executable).unwrap();
    let set_status = |online: bool, remote_ip: &str| {
        let content = serde_json::json!({
            "BackendState": if online { "Running" } else { "Stopped" },
            "Self": { "ID": "self", "Online": online, "TailscaleIPs": ["100.101.2.3"] },
            "Peer": { "nodekey:remote": { "ID": "worker", "Online": true, "TailscaleIPs": [remote_ip] } }
        });
        let next = dir.path().join("latest.json");
        fs::write(&next, content.to_string()).unwrap();
        fs::rename(next, executable.with_extension("json")).unwrap();
    };
    let discovery = MeshTailscale::new(MeshTailscaleConfig {
        tailscale_cli: executable.to_str().unwrap().to_owned(),
        ..Default::default()
    });
    let local = IdentityKeyPair::generate();
    let local_id = PeerId::from_public_key_bytes(local.public().as_bytes());
    let key = *IdentityKeyPair::generate().public().as_bytes();
    let remote_id = PeerId::from_public_key_bytes(&key);
    let store = PeerStore::new();
    store
        .add(TrustedPeer::new(
            remote_id,
            hex::encode(key),
            "worker".into(),
        ))
        .unwrap();
    let cfg: Config = toml::from_str(&format!(
        r#"
        [mesh]
        transports = ["iroh", "tailscale"]
        [scheduler]
        relay = false
        [[scheduler.tailnet_peers]]
        public_key = "{}"
        node_id = "worker"
        port = 9000
    "#,
        hex::encode(key)
    ))
    .unwrap();

    set_status(true, "100.64.1.1");
    let mesh = tokio::time::timeout(
        Duration::from_secs(10),
        prepare_with_discovery(
            &cfg,
            &local,
            &store,
            local_id,
            discovery,
            Duration::from_millis(50),
        ),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    let mut active = mesh.active_transports.clone();
    assert_eq!(&*active.borrow_and_update(), &["iroh", "tailscale"]);
    assert_eq!(mesh.peer_ids, [remote_id]);
    assert_eq!(
        mesh.addresses.lookup(&remote_id).unwrap().addr,
        "100.64.1.1:9000".parse().unwrap()
    );

    set_status(false, "100.64.1.1");
    tokio::time::timeout(Duration::from_secs(5), active.changed())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&*active.borrow_and_update(), &["iroh"]);
    assert!(mesh.addresses.lookup(&remote_id).is_none());

    set_status(true, "100.64.1.2");
    tokio::time::timeout(Duration::from_secs(5), active.changed())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&*active.borrow_and_update(), &["iroh", "tailscale"]);
    assert_eq!(
        mesh.addresses.lookup(&remote_id).unwrap().addr,
        "100.64.1.2:9000".parse().unwrap()
    );

    mesh.transport.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn missing_mixed_route_wakes_local_status_and_hung_queries_leave_listener_intact() {
    use entangle_mesh_tailscale::MeshTailscaleConfig;
    use std::{fs, os::unix::fs::symlink, path::Path, process::Stdio};
    use tokio::time::{sleep, timeout};

    async fn wait_for_call(path: &Path, count: usize) -> u32 {
        timeout(Duration::from_secs(3), async {
            loop {
                let calls = fs::read_to_string(path).unwrap_or_default();
                if let Some(pid) = calls.lines().nth(count - 1) {
                    return pid.parse().unwrap();
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("local status call started")
    }

    async fn wait_for_child_exit(pid: u32) {
        timeout(Duration::from_secs(3), async {
            loop {
                let alive = tokio::process::Command::new("kill")
                    .args(["-0", &pid.to_string()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .await
                    .unwrap()
                    .success();
                if !alive {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("timed out or aborted command was reaped");
    }

    timeout(Duration::from_secs(15), async {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("counted fixture");
        let calls = executable.with_extension("calls");
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../entangle-mesh-tailscale/tests/fixtures/status-cli.sh");
        symlink(fixture, &executable).unwrap();
        let set_status = |online| {
            let state = serde_json::json!({
                "BackendState": "Running",
                "Self": { "ID": "local", "Online": true, "TailscaleIPs": ["100.101.2.3"] },
                "Peer": { "key": { "ID": "worker", "Online": online, "TailscaleIPs": ["100.64.1.2"] } }
            });
            let next = dir.path().join("latest.json");
            fs::write(&next, state.to_string()).unwrap();
            fs::rename(next, executable.with_extension("json")).unwrap();
        };
        set_status(false);
        let mesh = MeshTailscale::new(MeshTailscaleConfig {
            tailscale_cli: executable.to_str().unwrap().to_owned(),
            ..Default::default()
        });
        let local = IdentityKeyPair::generate();
        let local_id = PeerId::from_public_key_bytes(local.public().as_bytes());
        let key = *IdentityKeyPair::generate().public().as_bytes();
        let worker = PeerId::from_public_key_bytes(&key);
        let absent_key = *IdentityKeyPair::generate().public().as_bytes();
        let absent = PeerId::from_public_key_bytes(&absent_key);
        let store = PeerStore::new();
        let cfg: Config = toml::from_str(&format!(
            r#"
            [mesh]
            transports = ["iroh", "tailscale"]
            [scheduler]
            bind = "0.0.0.0:0"
            relay = false
            [[scheduler.tailnet_peers]]
            public_key = "{}"
            node_id = "worker"
            port = 7443
            [[scheduler.tailnet_peers]]
            public_key = "{}"
            node_id = "absent"
            port = 7443
            "#,
            hex::encode(key),
            hex::encode(absent_key)
        ))
        .unwrap();
        let mut prepared =
            prepare_with_discovery(&cfg, &local, &store, local_id, mesh, Duration::from_secs(60))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(fs::read_to_string(&calls).unwrap().lines().count(), 1);
        assert_eq!(prepared.addresses.lookup_for_dispatch(&worker), (None, false));
        store.add(TrustedPeer::new(worker, hex::encode(key), "worker".into())).unwrap();
        store.add(TrustedPeer::new(absent, hex::encode(absent_key), "absent".into())).unwrap();
        assert_eq!(prepared.addresses.lookup_for_dispatch(&worker), (None, true));
        assert_eq!(prepared.addresses.lookup_for_dispatch(&local_id), (None, false));
        set_status(true);
        prepared.addresses.refresh_missing_route().await;
        let (route, refresh) = prepared.addresses.lookup_for_dispatch(&worker);
        assert!(!refresh);
        assert_eq!(route.unwrap().addr, "100.64.1.2:7443".parse().unwrap());
        assert_eq!(fs::read_to_string(&calls).unwrap().lines().count(), 2);

        fs::write(executable.with_extension("hang"), "").unwrap();
        sleep(Duration::from_secs(1)).await;
        assert_eq!(prepared.addresses.lookup_for_dispatch(&absent), (None, true));
        prepared.addresses.refresh_missing_route().await;
        let pid = wait_for_call(&calls, 3).await;
        wait_for_child_exit(pid).await;
        assert!(prepared.addresses.lookup(&worker).is_some());
        assert_eq!(&*prepared.active_transports.borrow(), &["iroh", "tailscale"]);

        sleep(Duration::from_secs(1)).await;
        let addresses = prepared.addresses.clone();
        let waiter = tokio::spawn(async move { addresses.refresh_missing_route().await });
        let pid = wait_for_call(&calls, 4).await;
        prepared.shutdown().await;
        waiter.await.unwrap();
        wait_for_child_exit(pid).await;
        assert_eq!(fs::read_to_string(&calls).unwrap().lines().count(), 4);
    })
    .await
    .expect("bounded local route polls and shutdown");
}

#[test]
fn tailnet_routes_on_a_mixed_endpoint_preserve_static_hints() {
    let key = *IdentityKeyPair::generate().public().as_bytes();
    let id = PeerId::from_public_key_bytes(&key);
    let store = PeerStore::new();
    store
        .add(TrustedPeer::new(id, hex::encode(key), "remote".into()))
        .unwrap();
    let mut static_peers = HashMap::new();
    static_peers.insert(
        id,
        IrohPeer::new(key, "192.0.2.7:7111".parse::<SocketAddr>().unwrap()),
    );
    let addresses = SchedulerAddresses {
        lan: None,
        static_peers,
        tailnet: RwLock::new(snapshot_routes(
            &status(),
            &[Mapping {
                node_id: "worker".into(),
                public_key: key,
                port: 7300,
            }],
            "0.0.0.0:0".parse().unwrap(),
        )),
        tailnet_demand: None,
        trust: PeerStoreAllowlist::new(store),
    };
    let dial = addresses.lookup(&id).unwrap();
    assert_eq!(
        dial.addrs().collect::<Vec<_>>(),
        vec![
            "192.0.2.7:7111".parse::<SocketAddr>().unwrap(),
            "100.64.22.9:7300".parse().unwrap(),
        ]
    );
    *addresses.tailnet.write().unwrap() = HashMap::new();
    assert_eq!(addresses.lookup(&id).unwrap().addr, dial.addr);
}

#[test]
fn lan_hints_require_a_matching_key_and_an_explicit_reachable_scheduler_port() {
    let key = *IdentityKeyPair::generate().public().as_bytes();
    let id = PeerId::from_public_key_bytes(&key);
    let mut seen = PeerSeen {
        peer_id: id,
        public_key: Some(key),
        mesh_port: Some(4777),
        port: 7001,
        display_name: "worker".into(),
        addresses: ["0.0.0.0", "224.0.0.251", "127.0.0.1", "::1", "192.168.0.2"]
            .map(|s| s.parse().unwrap())
            .into(),
        version: String::new(),
        hardware: None,
        last_seen: std::time::SystemTime::now(),
    };
    let bind = "0.0.0.0:90".parse().unwrap();
    let peer = lan_peer(&seen, bind).unwrap();
    assert_eq!(peer.public_key, key);
    assert_eq!(
        peer.addrs().collect::<Vec<_>>(),
        ["192.168.0.2:4777".parse::<SocketAddr>().unwrap()]
    );
    seen.peer_id = PeerId::from_public_key_bytes(&[0; 32]);
    assert!(lan_peer(&seen, bind).is_none());
    seen.peer_id = id;
    seen.mesh_port = None;
    assert!(lan_peer(&seen, bind).is_none());
    seen.mesh_port = Some(0);
    assert!(lan_peer(&seen, bind).is_none());
    seen.mesh_port = Some(9);
    seen.public_key = None;
    assert!(lan_peer(&seen, bind).is_none());
}
