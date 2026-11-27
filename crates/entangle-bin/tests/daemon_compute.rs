//! A signed component installed on one daemon is scheduled from another over
//! authenticated QUIC, with the real UDS RPC and persistent trust stores.
#![cfg(unix)]

#[path = "common/plugin.rs"]
mod plugin;

#[path = "common/dispatch_benchmark.rs"]
mod benchmark;

#[path = "common/inference.rs"]
mod inference;

use std::fs;
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use entangle_peers::{PeerStore, TrustedPeer};
use entangle_rpc::{Client, ComputeDispatchParams, ComputeIntegrity, RpcError};
use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;
use tokio::time::{sleep, timeout};

struct Node {
    home: PathBuf,
    identity: IdentityKeyPair,
}

impl Node {
    fn new(home: PathBuf) -> Self {
        let identity = IdentityKeyPair::generate();
        let config = home.join(".entangle");
        fs::create_dir_all(&config).unwrap();
        fs::write(config.join("identity.key"), identity.to_pem()).unwrap();
        Self { home, identity }
    }

    fn peer_id(&self) -> PeerId {
        PeerId::from_public_key_bytes(self.identity.public().as_bytes())
    }

    fn public_key(&self) -> String {
        hex::encode(self.identity.public().as_bytes())
    }

    fn peers(&self) -> PeerStore {
        PeerStore::open(self.home.join(".entangle/peers.toml")).unwrap()
    }

    fn configure(
        &self,
        peer: &Node,
        bind: SocketAddr,
        route: Option<SocketAddr>,
        transports: &[&str],
    ) {
        self.peers()
            .add(TrustedPeer::new(
                peer.peer_id(),
                peer.public_key(),
                "test peer".into(),
            ))
            .unwrap();
        let routes = route
            .map(|addr| format!("\"{}@{addr}\"", peer.public_key()))
            .unwrap_or_default();
        let config = format!(
            "[mesh]\ntransports={transports:?}\nmulti_node=true\n\n[scheduler]\nbind=\"{bind}\"\nrelay=false\npeers=[{routes}]\n"
        );
        fs::write(self.home.join(".entangle/config.toml"), config).unwrap();
    }

    async fn start(&self, binary: &Path, transports: &[&str]) -> Daemon {
        let child = Command::new(binary)
            .arg("run")
            .env("HOME", &self.home)
            .env("TOKIO_WORKER_THREADS", "2")
            .env("RAYON_NUM_THREADS", "2")
            .env("RUST_LOG", "warn")
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn entangled");
        let client = Client::new(self.home.join(".entangle/sock"));
        let mut daemon = Daemon { child, client };
        loop {
            assert_eq!(
                daemon.child.try_wait().unwrap(),
                None,
                "daemon exited before startup"
            );
            if let Ok(status) = daemon.client.mesh_status().await {
                assert_eq!(status.local_peer_id, self.peer_id().to_hex());
                assert_eq!(status.transports_active, transports);
                return daemon;
            }
            sleep(Duration::from_millis(40)).await;
        }
    }
}

struct Daemon {
    child: Child,
    client: Client,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Cluster {
    coordinator: Node,
    worker: Node,
    executor: Daemon,
    submitter: Daemon,
    plugin_id: String,
    package_load: Duration,
}

async fn start_cluster(dir: &Path, binary: &Path) -> Cluster {
    start_cluster_with_routes(dir, binary, false).await
}

async fn start_cluster_with_routes(dir: &Path, binary: &Path, lan: bool) -> Cluster {
    let coordinator = Node::new(dir.join("a"));
    let worker = Node::new(dir.join("b"));
    let publisher = IdentityKeyPair::generate();
    plugin::keyring_for(&publisher)
        .save(&worker.home.join(".entangle/keyring.toml"))
        .unwrap();
    let package = dir.join("package");
    fs::create_dir(&package).unwrap();
    let plugin_id = plugin::write_plugin_package(&package, &publisher, &plugin::hello_pong_wasm());

    let transports: &[&str] = if lan { &["local", "iroh"] } else { &["iroh"] };
    if lan {
        // Neither daemon knows the other's port. Only a live, correctly
        // keyed mDNS advertisement can make the worker dialable.
        let bind = "0.0.0.0:0".parse().unwrap();
        worker.configure(&coordinator, bind, None, transports);
        coordinator.configure(&worker, bind, None, transports);
    } else {
        let port = UdpSocket::bind("127.0.0.1:0").unwrap();
        let worker_addr = port.local_addr().unwrap();
        worker.configure(&coordinator, worker_addr, None, transports);
        coordinator.configure(
            &worker,
            "127.0.0.1:0".parse().unwrap(),
            Some(worker_addr),
            transports,
        );
    }
    let executor = worker.start(binary, transports).await;
    let started = Instant::now();
    assert_eq!(
        executor
            .client
            .plugins_load(&package)
            .await
            .unwrap()
            .plugin_id,
        plugin_id
    );
    let package_load = started.elapsed();
    let submitter = coordinator.start(binary, transports).await;
    assert!(submitter
        .client
        .plugins_list()
        .await
        .unwrap()
        .plugins
        .is_empty());

    Cluster {
        coordinator,
        worker,
        executor,
        submitter,
        plugin_id,
        package_load,
    }
}

fn request(plugin: &str) -> ComputeDispatchParams {
    ComputeDispatchParams {
        plugin_id: plugin.to_owned(),
        input: b"mesh worker".to_vec(),
        timeout_ms: 5_000,
        // A positive requirement forces an actual worker advertisement.
        cpu_cores: 0.01,
        memory_bytes: 0,
        gpu_required: false,
        gpu_vram_min_bytes: 0,
        integrity: ComputeIntegrity::None,
    }
}

async fn first_remote(cluster: &Cluster) -> (entangle_rpc::ComputeDispatchResult, Duration) {
    loop {
        let start = Instant::now();
        match cluster
            .submitter
            .client
            .compute_dispatch(request(&cluster.plugin_id))
            .await
        {
            Ok(result) => return (result, start.elapsed()),
            Err(RpcError::Rpc { message, .. }) if message.contains("no live workers") => {
                // Capability polling and the UDS listener start concurrently.
                sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("dispatch failed: {error}"),
        }
    }
}

#[tokio::test]
async fn first_submission_replans_after_a_trusted_worker_hot_load() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let cluster = timeout(
        Duration::from_secs(20),
        start_cluster(dir.path(), Path::new(env!("CARGO_BIN_EXE_entangled"))),
    )
    .await
    .expect("cold daemon setup did not finish");
    timeout(Duration::from_secs(8), async {
        // Ensure the authenticated initial inventory existed before the new package was loaded.
        first_remote(&cluster).await;
        let publisher = IdentityKeyPair::generate();
        let package = dir.path().join("hot-package");
        fs::create_dir(&package).unwrap();
        let id = plugin::write_plugin_package(&package, &publisher, &plugin::hello_pong_wasm());
        for (node, daemon) in [
            (&cluster.worker, &cluster.executor),
            (&cluster.coordinator, &cluster.submitter),
        ] {
            plugin::keyring_for(&publisher)
                .save(&node.home.join(".entangle/keyring.toml"))
                .unwrap();
            assert_eq!(
                daemon
                    .client
                    .plugins_load(&package)
                    .await
                    .unwrap()
                    .plugin_id,
                id
            );
        }
        // This deliberately removes the CPU requirement and gives both nodes
        // the package. An explicit remote allowlist must still exclude self.
        let allowed = cluster.worker.peer_id().to_hex();
        let params = ComputeDispatchParams {
            cpu_cores: 0.0,
            integrity: ComputeIntegrity::TrustedExecutor {
                allowlist: vec![allowed.clone()],
            },
            ..request(&id)
        };
        let result = cluster
            .submitter
            .client
            .compute_dispatch(&params)
            .await
            .unwrap();
        assert_eq!(result.chosen_peer, allowed);
        assert_eq!(result.output, b"Hello, mesh worker!");
        let metrics = cluster.executor.client.metrics().await.unwrap();
        assert!(metrics.contains("entangle_wasm_invocation_seconds_count{result=\"ok\"} 2\n"));
        let metrics = cluster.submitter.client.metrics().await.unwrap();
        assert!(!metrics.contains("entangle_wasm_invocation_seconds_count{result=\"ok\"}"));
    })
    .await
    .expect("the first request should complete before the 15-second polling tick");
}

async fn exercise(dir: &Path) {
    let cluster = start_cluster(dir, Path::new(env!("CARGO_BIN_EXE_entangled"))).await;
    let (result, _) = first_remote(&cluster).await;
    assert_eq!(result.chosen_peer, cluster.worker.peer_id().to_hex());
    assert_eq!(result.output, b"Hello, mesh worker!");

    let worker_metrics = cluster.executor.client.metrics().await.unwrap();
    assert!(worker_metrics.contains("entangle_plugins_loaded 1\n"));
    assert!(worker_metrics.contains("entangle_wasm_invocation_seconds_count{result=\"ok\"} 1\n"));
    let coordinator_metrics = cluster.submitter.client.metrics().await.unwrap();
    assert!(coordinator_metrics.contains("entangle_plugins_loaded 0\n"));
    assert!(coordinator_metrics
        .contains("entangle_compute_dispatch_seconds_count{result=\"remote\"} 1\n"));

    // The same healthy worker must be excluded when the task exceeds its capacity.
    let oversized = ComputeDispatchParams {
        cpu_cores: f32::MAX,
        ..request(&cluster.plugin_id)
    };
    let err = cluster
        .submitter
        .client
        .compute_dispatch(oversized)
        .await
        .unwrap_err();
    assert!(
        matches!(err, RpcError::Rpc { code: -32000, ref message } if message.contains("no worker satisfies")),
        "{err}"
    );

    cluster
        .worker
        .peers()
        .revoke(&cluster.coordinator.peer_id())
        .unwrap();
    let err = cluster
        .submitter
        .client
        .compute_dispatch(request(&cluster.plugin_id))
        .await
        .unwrap_err();
    assert!(
        matches!(err, RpcError::Rpc { code: -32000, ref message } if message.contains("not-authorized")),
        "{err}"
    );
}

#[tokio::test]
async fn schedules_on_another_daemon_and_enforces_live_revocation() {
    // A short path also fits Darwin's sockaddr_un.
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    timeout(Duration::from_secs(45), exercise(dir.path()))
        .await
        .expect("two-daemon compute round trip timed out");
}

/// An operator knows this key, but the announcement has no matching QUIC
/// scheduler. Its claimed hardware must never enter task placement.
async fn check_unverified_lan_advert(cluster: &Cluster) {
    use entangle_mesh_local::{Discovery, DiscoveryConfig, HardwareAdvert, LocalPeer};

    let identity = IdentityKeyPair::generate();
    let key = *identity.public().as_bytes();
    let id = PeerId::from_public_key_bytes(&key);
    cluster
        .coordinator
        .peers()
        .add(TrustedPeer::new(id, hex::encode(key), "known".into()))
        .unwrap();
    let idle = UdpSocket::bind("0.0.0.0:0").unwrap();
    let addr = idle.local_addr().unwrap();
    let beacon = Discovery::new(DiscoveryConfig {
        local: LocalPeer {
            peer_id: id,
            display_name: "unverified".into(),
            port: addr.port(),
            version: "1".into(),
            hardware: Some(HardwareAdvert {
                cpu_cores: 32.0,
                memory_bytes: 1 << 30,
                gpu_backend: None,
                gpu_vram_bytes: 0,
                network_bandwidth_bps: 0,
                npu_vendor: None,
            }),
        },
        announce_interval_secs: 30,
        channel_capacity: 16,
    })
    .unwrap()
    .with_bound_transport(key, addr);
    beacon.start_announcing().unwrap();
    let id = id.to_hex();
    for expect_visible in [true, false] {
        if !expect_visible {
            beacon.shutdown().unwrap();
        }
        loop {
            let peers = cluster.submitter.client.mesh_peers().await.unwrap();
            let known = peers
                .peers
                .iter()
                .find(|p| p.peer_id == id)
                .expect("a paired peer remains listed after its mDNS goodbye");
            assert!(known.trusted);
            assert_eq!(
                known.display_name, "known",
                "the stored name is authoritative"
            );
            if known.addresses.is_empty() != expect_visible {
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
        // The ordinary daemon RPC adapts legacy compute plugins into a bounded
        // stream. Recheck detached signatures independently on the client.
        use entangle_types::task::{
            ChannelSpec, IntegrityPolicy, PartialResultPolicy, StreamingTask, TaskId,
        };
        let task = StreamingTask {
            id: TaskId::new_v4(),
            plugin: cluster.plugin_id.parse().unwrap(),
            channel: ChannelSpec {
                max_chunk_bytes: 4,
                credit_window: 1,
                ..Default::default()
            },
            resources: Default::default(),
            integrity: IntegrityPolicy::TrustedExecutor {
                allowlist: vec![cluster.worker.peer_id()],
            },
            timeout_ms: 5000,
            partial_result: PartialResultPolicy::KeepSigned,
        };
        let handle = cluster
            .submitter
            .client
            .stream_open(&entangle_rpc::StreamOpenParams {
                task: task.clone(),
                input: b"rpc".to_vec(),
            })
            .await
            .unwrap();
        assert_eq!(handle.executor, cluster.worker.peer_id());
        let mut all = Vec::new();
        let mut seq = 0;
        loop {
            match cluster
                .submitter
                .client
                .stream_read(&handle.session)
                .await
                .unwrap()
            {
                entangle_rpc::StreamRead::Waiting => continue,
                entangle_rpc::StreamRead::Chunk {
                    seq: received,
                    timestamp_ms,
                    signature,
                    bytes,
                } => {
                    let chunk = entangle_scheduler::stream::SignedChunk {
                        seq: received,
                        timestamp_ms,
                        signature,
                        bytes,
                    };
                    chunk
                        .verify(&cluster.worker.identity.public(), task.id, seq)
                        .unwrap();
                    all.extend_from_slice(&chunk.bytes);
                    seq += 1;
                }
                entangle_rpc::StreamRead::Finished => break,
                entangle_rpc::StreamRead::Stalled => panic!("consumer supplied credit"),
            }
        }
        assert_eq!(all, b"Hello, rpc!");
        let mut job = request(&cluster.plugin_id);
        job.integrity = ComputeIntegrity::TrustedExecutor {
            allowlist: vec![id.clone()],
        };
        let err = cluster
            .submitter
            .client
            .compute_dispatch(job)
            .await
            .unwrap_err();
        assert!(
            matches!(err, RpcError::Rpc { ref message, .. } if message.contains("no live workers")),
            "{err}"
        );
    }
}

/// A healthy authenticated worker may lose authorization after a session opens.
#[tokio::test]
async fn stream_delivery_rechecks_persisted_worker_trust() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    timeout(Duration::from_secs(35), async {
        let cluster = start_cluster(dir.path(), Path::new(env!("CARGO_BIN_EXE_entangled"))).await;
        first_remote(&cluster).await;
        let worker = cluster.worker.peer_id();
        let store_path = cluster.coordinator.home.join(".entangle/peers.toml");
        let original = fs::read(&store_path).unwrap();
        for corrupt in [false, true] {
            use entangle_types::task::{
                ChannelSpec, IntegrityPolicy, PartialResultPolicy, StreamingTask, TaskId,
            };
            let session = cluster
                .submitter
                .client
                .stream_open(&entangle_rpc::StreamOpenParams {
                    task: StreamingTask {
                        id: TaskId::new_v4(),
                        plugin: cluster.plugin_id.parse().unwrap(),
                        channel: ChannelSpec {
                            credit_window: 2,
                            max_chunk_bytes: 2,
                            ..Default::default()
                        },
                        integrity: IntegrityPolicy::TrustedExecutor {
                            allowlist: vec![worker],
                        },
                        resources: Default::default(),
                        partial_result: PartialResultPolicy::KeepSigned,
                        timeout_ms: 5000,
                    },
                    input: b"rpc".to_vec(),
                })
                .await
                .unwrap()
                .session;
            loop {
                match cluster
                    .submitter
                    .client
                    .stream_read(&session)
                    .await
                    .unwrap()
                {
                    entangle_rpc::StreamRead::Waiting => continue,
                    entangle_rpc::StreamRead::Chunk { bytes, .. } => {
                        assert_eq!(bytes, b"He");
                        break;
                    }
                    other => panic!("unexpected first event {other:?}"),
                }
            }
            if corrupt {
                fs::write(&store_path, "malformed = [").unwrap();
            } else {
                cluster.coordinator.peers().revoke(&worker).unwrap();
            }
            let rejected = cluster
                .submitter
                .client
                .stream_read(&session)
                .await
                .unwrap_err();
            assert!(
                matches!(rejected, RpcError::Rpc { ref message, .. }
                if message.contains("stream worker is no longer authorized")),
                "{rejected}"
            );
            fs::write(&store_path, &original).unwrap();
        }
    })
    .await
    .expect("active-stream revocation did not finish");
}

/// Requires two local processes to receive multicast DNS through a host interface.
#[tokio::test]
#[ignore = "requires working host multicast DNS"]
async fn discovers_and_runs_work_without_a_configured_peer_address() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    timeout(Duration::from_secs(50), async {
        let cluster =
            start_cluster_with_routes(dir.path(), Path::new(env!("CARGO_BIN_EXE_entangled")), true)
                .await;
        let (result, _) = first_remote(&cluster).await;
        assert_eq!(result.chosen_peer, cluster.worker.peer_id().to_hex());
        assert_eq!(result.output, b"Hello, mesh worker!");
        check_unverified_lan_advert(&cluster).await;
        cluster
            .coordinator
            .peers()
            .revoke(&cluster.worker.peer_id())
            .unwrap();
        let peers = cluster.submitter.client.mesh_peers().await.unwrap();
        let sighting = peers.peers.iter().find(|p| p.peer_id == result.chosen_peer)
            .expect("the running worker is still advertising after revocation");
        assert!(!sighting.trusted);
        assert!(!sighting.addresses.is_empty());
        let error = cluster
            .submitter
            .client
            .compute_dispatch(request(&cluster.plugin_id))
            .await
            .expect_err("a discovered but revoked worker must lose its route");
        assert!(matches!(error, RpcError::Rpc { ref message, .. } if message.contains("no known network address") || message.contains("no live workers")), "{error}");
    })
    .await
    .expect("mDNS-only two-daemon dispatch timed out");
}
