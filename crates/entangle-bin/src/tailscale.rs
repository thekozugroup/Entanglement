//! Daemon wiring for the `mesh.tailscale` transport (spec §6.1.1).
//!
//! Off unless `[mesh.tailscale] enabled = true` **and** `[mesh] transports`
//! contains `"tailscale"`. When on, the daemon starts the identity-bound TCP
//! listener, the liveness poller, a discovery task that re-enumerates
//! tailnet peers every 60 s while the tailnet is active, and serves the
//! scheduler protocols on the listener — `entangle/scheduler/1` and
//! `entangle/stream/1`, selected per connection
//! ([`entangle_scheduler::serve_tailscale`]) — with the same task and stream
//! servers (and so the same peer-store allowlist) as the iroh endpoint.
//! Outbound, the tailnet is one of the transports the dispatcher's router
//! picks from per peer (see `crate::mesh`).

use std::sync::Arc;
use std::time::Duration;

use entangle_mesh_tailscale::TailscalePeer;
use entangle_mesh_tailscale::{
    AclMode, LivenessHandle, LivenessSnapshot, MeshTailscale, MeshTailscaleConfig, PeerAllowlist,
    TailscaleStatus,
};
use entangle_peers::{PeerStore, TrustLevel};
use entangle_scheduler::{RemoteTaskServer, StreamServer, WorkerInfo, WorkerPool};
use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;
use tokio::sync::watch;

use crate::config::MeshConfig;

/// `true` when the daemon should run the `mesh.tailscale` transport.
///
/// Logs a warning when `[mesh.tailscale] enabled = true` but `[mesh]
/// transports` does not list `"tailscale"`: the operator asked for the
/// transport, yet it stays off (the daemon calls this once at startup).
pub fn enabled(mesh: &MeshConfig) -> bool {
    let listed = mesh.transports.iter().any(|t| t == "tailscale");
    if mesh.tailscale.enabled && !listed {
        tracing::warn!(
            transports = ?mesh.transports,
            "[mesh.tailscale] enabled = true, but [mesh] transports does not list \"tailscale\": \
             the transport stays off (add it to transports, or set enabled = false)"
        );
    }
    mesh.tailscale.enabled && listed
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
    let defaults = MeshTailscaleConfig::default();
    Ok(MeshTailscaleConfig {
        tailscale_cli: mesh.tailscale.tailscale_cli.clone(),
        acl_mode,
        allowlist: Some(Arc::new(StoreAllowlist(store))),
        port: mesh.tailscale.port,
        bind_ip: mesh.tailscale.bind_ip.unwrap_or(defaults.bind_ip),
        // The scheduler's frames: one maximum task input plus envelope, the
        // same ceiling the iroh endpoint applies.
        max_frame_bytes: entangle_mesh_iroh::MAX_FRAME_BYTES,
        ..defaults
    })
}

/// Feeds tailnet-discovered peers into the scheduler's worker pool.
///
/// Placement only considers pool members, and mDNS is the only other feeder,
/// so without this a peer reachable over the tailnet alone could never be
/// chosen for remote work. Only trusted, non-revoked peers are added.
/// A tailnet probe says nothing about hardware, so a peer the pool already
/// knows (from mDNS) keeps its advertised capabilities and is only
/// refreshed; a peer new to the pool gets a conservative default
/// (one core, no memory, no GPU), so only light tasks are placed on it
/// until an mDNS advert says more. Entries this feeder added are
/// removed again when the peer leaves the candidate set or the tailnet
/// stops being active.
pub struct TailnetWorkers {
    pool: WorkerPool,
    store: PeerStore,
    local_peer: PeerId,
    added: std::sync::Mutex<std::collections::HashSet<PeerId>>,
}

impl TailnetWorkers {
    /// A feeder for `pool`, gated by `store`'s trust records.
    pub fn new(pool: WorkerPool, store: PeerStore, local_peer: PeerId) -> Self {
        Self {
            pool,
            store,
            local_peer,
            added: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// Make the pool reflect `candidates` (one discovery round).
    pub fn sync(&self, candidates: &[TailscalePeer]) {
        let mut added = self.added.lock().unwrap_or_else(|e| e.into_inner());
        let mut present = std::collections::HashSet::new();
        for c in candidates {
            if c.peer_id == self.local_peer {
                continue;
            }
            let Some(record) = self.store.get(&c.peer_id) else {
                continue;
            };
            if record.trust == TrustLevel::Revoked {
                continue;
            }
            present.insert(c.peer_id);
            let known = self
                .pool
                .live(Duration::MAX)
                .into_iter()
                .find(|w| w.peer_id == c.peer_id);
            match known {
                // Keep what mDNS (or an earlier round) recorded; refresh it.
                Some(info) => {
                    self.pool.upsert(info);
                }
                None => {
                    let name = if record.display_name.is_empty() {
                        c.magic_dns.clone()
                    } else {
                        record.display_name.clone()
                    };
                    if self.pool.upsert(default_worker(c.peer_id, name)) {
                        added.insert(c.peer_id);
                    }
                }
            }
        }
        // Peers this feeder added that the tailnet no longer offers.
        let gone: Vec<PeerId> = added.difference(&present).copied().collect();
        for id in gone {
            self.pool.remove(&id);
            added.remove(&id);
        }
    }

    /// The tailnet is not active: forget every peer this feeder added.
    pub fn clear(&self) {
        self.sync(&[]);
    }
}

/// What the pool knows about a peer seen only over the tailnet.
fn default_worker(peer_id: PeerId, display_name: String) -> WorkerInfo {
    WorkerInfo {
        peer_id,
        display_name,
        cpu_cores: 1.0,
        memory_bytes: 0,
        gpu: None,
        npu: None,
        network_bandwidth_bps: 0,
        rtt_ms: 20,
        load: 0.0,
        cost: 1.0,
    }
}

/// How often discovery re-enumerates the tailnet while it is active.
pub const DISCOVERY_INTERVAL: Duration = Duration::from_secs(60);

/// The discovery task: a round every `every` and on each liveness change,
/// while the tailnet is active. Whenever it is not active the candidate set
/// is cleared, so no peer stays reachable via a tailnet that is down (spec
/// §6.1.1 degradation); the next active round re-enumerates. Returns when
/// the liveness poller goes away.
pub async fn run_discovery(
    t: MeshTailscale,
    mut state: watch::Receiver<LivenessSnapshot>,
    status: watch::Receiver<Option<Arc<TailscaleStatus>>>,
    every: Duration,
    workers: Option<Arc<TailnetWorkers>>,
) {
    loop {
        if state.borrow().is_active() {
            let snapshot = status.borrow().clone();
            if let Some(st) = snapshot {
                let found = t.discover(&st).await;
                tracing::debug!(candidates = found.len(), "mesh.tailscale discovery round");
                if let Some(w) = &workers {
                    w.sync(&found);
                }
            }
        } else {
            let dropped = t.clear_candidates();
            if let Some(w) = &workers {
                w.clear();
            }
            if dropped > 0 {
                tracing::info!(
                    dropped,
                    "mesh.tailscale: tailnet not active, tailnet peers marked unreachable"
                );
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(every) => {}
            r = state.changed() => if r.is_err() { return },
        }
    }
}

/// Keep `entangle_mesh_tailscale_state{state}` equal to the liveness poller's
/// confirmed state: a one-hot gauge over `active` / `stopped` /
/// `uninstalled` / `unknown` (`unknown` until the first poll completes).
///
/// Call it only when the transport runs, so the gauge exists exactly when the
/// transport does. Returns when the poller (the channel's sender) goes away.
pub fn spawn_state_metrics(
    registry: entangle_observability::Registry,
    mut state: watch::Receiver<LivenessSnapshot>,
) -> tokio::task::JoinHandle<()> {
    let publish = move |snap: &LivenessSnapshot, registry: &entangle_observability::Registry| {
        let label = snap.state.as_ref().map_or("unknown", |s| s.label());
        entangle_observability::catalog::tailscale_state(registry, label);
    };
    publish(&state.borrow(), &registry);
    tokio::spawn(async move {
        while state.changed().await.is_ok() {
            let snap = state.borrow_and_update().clone();
            publish(&snap, &registry);
        }
    })
}

/// The boot-time version check (spec §11 #17): refuse to enable the
/// transport on a `tailscale` older than
/// [`entangle_mesh_tailscale::MIN_SUPPORTED_VERSION`] (`ENTANGLE-E0791`).
///
/// Both versions that can be read are held to the floor: the CLI's
/// (`tailscale version`) and tailscaled's (`Version` in `status --json`,
/// whose output the transport trusts). When the CLI is there but cannot say
/// its version, tailscaled's stands in; with neither the transport is
/// refused (`ENTANGLE-E0793`) rather than started unchecked
/// ([`entangle_mesh_tailscale::check_versions`]). A CLI that does not exist
/// at all does not block the start — the liveness poller then reports the
/// tailnet as `uninstalled` (or `stopped`, when tailscaled's socket exists),
/// and there is no status JSON to trust — but it is logged. Returns the
/// version when one was read.
pub async fn check_version(
    mesh: &MeshConfig,
) -> anyhow::Result<Option<entangle_mesh_tailscale::TailscaleVersion>> {
    let source =
        entangle_mesh_tailscale::CliStatusSource::new(if mesh.tailscale.tailscale_cli.is_empty() {
            "tailscale"
        } else {
            mesh.tailscale.tailscale_cli.as_str()
        });
    let cli = match source.fetch_version().await {
        Ok(v) => Ok(v),
        Err(entangle_mesh_tailscale::MeshTailscaleError::NotInstalled) => {
            tracing::warn!(
                cli = source.cli(),
                minimum = %entangle_mesh_tailscale::MIN_SUPPORTED_VERSION,
                "mesh.tailscale: the tailscale CLI was not found; its version is checked again \
                 at every liveness transition"
            );
            return Ok(None);
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                cli = source.cli(),
                "mesh.tailscale: could not read the CLI's version; checking tailscaled's"
            );
            Err(e.to_string())
        }
    };
    // tailscaled may be down at boot: then only the CLI's version is known.
    let daemon = source
        .fetch_status()
        .await
        .ok()
        .and_then(|s| s.parsed_version());
    let v = entangle_mesh_tailscale::check_versions(cli, daemon)?;
    tracing::info!(
        tailscale_version = %v,
        tailscaled_version = ?daemon.map(|d| d.to_string()),
        cli = source.cli(),
        "mesh.tailscale: host tailscale version"
    );
    Ok(Some(v))
}

/// Start the transport, serving loop, liveness poller and discovery task.
///
/// Refuses (before binding anything) when the host `tailscale` is older
/// than the supported minimum ([`check_version`]).
///
/// `tasks` / `streams` are served on the listener (pass the instances the
/// iroh endpoint serves, so in-flight tables and limits are shared); with
/// neither, a connection is closed after its protocol selection.
pub async fn start(
    mesh: &MeshConfig,
    identity: &IdentityKeyPair,
    store: PeerStore,
    tasks: Option<Arc<RemoteTaskServer>>,
    streams: Option<Arc<StreamServer>>,
    workers: Option<Arc<TailnetWorkers>>,
) -> anyhow::Result<TailscaleRuntime> {
    let cfg = build_config(mesh, store)?;
    check_version(mesh).await?;
    let liveness = cfg.spawn_liveness();
    let transport = MeshTailscale::start(identity, cfg).await?;
    tracing::info!(
        peer_id = %transport.local_peer_id(),
        addr = %transport.local_addr(),
        "mesh.tailscale transport listening",
    );

    let serve = tokio::spawn(entangle_scheduler::serve_tailscale(
        transport.clone(),
        tasks,
        streams,
    ));
    let discover = tokio::spawn(run_discovery(
        transport.clone(),
        liveness.state(),
        liveness.status(),
        DISCOVERY_INTERVAL,
        workers,
    ));
    Ok(TailscaleRuntime {
        transport,
        liveness,
        tasks: vec![serve, discover],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn logs_of(f: impl FnOnce()) -> String {
        let cap = Captured::default();
        let w = cap.clone();
        let sub = tracing_subscriber::fmt()
            .with_writer(move || w.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(sub, f);
        let bytes = cap.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    fn mesh(toml_text: &str) -> MeshConfig {
        toml::from_str::<crate::config::Config>(toml_text)
            .unwrap()
            .mesh
    }

    #[test]
    fn enabled_but_not_in_transports_is_inert_and_says_so() {
        let m = mesh("[mesh]\ntransports = [\"local\"]\n[mesh.tailscale]\nenabled = true\n");
        let text = logs_of(|| assert!(!enabled(&m)));
        assert!(text.contains("WARN"), "{text}");
        assert!(text.contains("transports"), "{text}");

        // Fully on, or fully off: nothing to warn about.
        let on = mesh("[mesh]\ntransports = [\"tailscale\"]\n[mesh.tailscale]\nenabled = true\n");
        assert!(logs_of(|| assert!(enabled(&on))).is_empty());
        let off = mesh("[mesh]\ntransports = [\"tailscale\"]\n");
        assert!(logs_of(|| assert!(!enabled(&off))).is_empty());
    }
}

#[cfg(all(test, unix))]
mod version_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn fake_cli(dir: &std::path::Path, version: &str) -> String {
        let path = dir.join(format!("tailscale-{version}"));
        // Written whole before it is made executable and spawned.
        std::fs::write(
            &path,
            format!("#!/bin/sh\ncase \"$1\" in version) echo {version} ;; *) exit 1 ;; esac\n"),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.display().to_string()
    }

    fn mesh_with(cli: String) -> MeshConfig {
        let mut cfg = crate::config::Config::default();
        cfg.mesh.transports = vec!["tailscale".into()];
        cfg.mesh.tailscale.enabled = true;
        cfg.mesh.tailscale.tailscale_cli = cli;
        cfg.mesh.tailscale.port = 0;
        cfg.mesh
    }

    /// Spec §11 #17: the daemon refuses to enable `mesh.tailscale` on a
    /// tailscale older than 1.62.0, before binding its listener.
    #[tokio::test]
    async fn boot_refuses_a_tailscale_below_the_floor() {
        let dir = tempfile::tempdir().unwrap();
        let old = mesh_with(fake_cli(dir.path(), "1.58.2"));
        let err = start(
            &old,
            &IdentityKeyPair::generate(),
            PeerStore::new(),
            None,
            None,
            None,
        )
        .await
        .err()
        .expect("an old tailscale is refused");
        let text = format!("{err:#}");
        assert!(
            text.contains("ENTANGLE-E0791") && text.contains("1.58.2"),
            "{text}"
        );

        let new = mesh_with(fake_cli(dir.path(), "1.62.0"));
        assert_eq!(
            check_version(&new).await.unwrap(),
            Some(entangle_mesh_tailscale::TailscaleVersion::new(1, 62, 0))
        );
        // Missing CLI: not a refusal (the poller reports `uninstalled`).
        let missing = mesh_with("/nonexistent/tailscale".into());
        assert_eq!(check_version(&missing).await.unwrap(), None);
    }

    /// A CLI whose `version` fails; `status --json` prints `status`, or
    /// fails too when it is `None`.
    fn mute_cli(dir: &std::path::Path, name: &str, status: Option<&str>) -> String {
        let path = dir.join(name);
        let status_arm = match status {
            Some(json) => format!("status) echo '{json}' ;;"),
            None => "status) exit 1 ;;".to_owned(),
        };
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\ncase \"$1\" in version) echo 'unknown command' >&2; exit 1 ;; \
                 {status_arm} *) exit 1 ;; esac\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.display().to_string()
    }

    /// The floor does not fail open: when `tailscale version` cannot say its
    /// version, tailscaled's (`status --json` `Version`) is checked instead,
    /// and with neither the transport is refused; a tailscaled below the
    /// floor is refused even when the CLI is new enough.
    #[tokio::test]
    async fn boot_does_not_start_on_an_unknown_or_old_tailscaled() {
        let dir = tempfile::tempdir().unwrap();
        let running = |v: &str| format!("{{\"Version\":\"{v}\",\"BackendState\":\"Running\"}}");

        let old = mesh_with(mute_cli(dir.path(), "old", Some(&running("1.50.0-t1"))));
        let text = format!("{:#}", check_version(&old).await.unwrap_err());
        assert!(
            text.contains("ENTANGLE-E0791") && text.contains("1.50.0"),
            "{text}"
        );

        let unknown = mesh_with(mute_cli(dir.path(), "unknown", None));
        let text = format!("{:#}", check_version(&unknown).await.unwrap_err());
        assert!(
            text.contains("ENTANGLE-E0793") && text.contains("1.62.0"),
            "{text}"
        );

        let new = mesh_with(mute_cli(dir.path(), "new", Some(&running("1.76.1-t1"))));
        assert_eq!(
            check_version(&new).await.unwrap(),
            Some(entangle_mesh_tailscale::TailscaleVersion::new(1, 76, 1))
        );

        // A new CLI in front of an old tailscaled.
        let path = dir.path().join("split");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\ncase \"$1\" in version) echo 1.76.1 ;; status) echo '{}' ;; \
                 *) exit 1 ;; esac\n",
                running("1.50.0")
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let split = mesh_with(path.display().to_string());
        let text = format!("{:#}", check_version(&split).await.unwrap_err());
        assert!(
            text.contains("ENTANGLE-E0791") && text.contains("1.50.0"),
            "{text}"
        );
    }
}

#[cfg(test)]
mod discovery_tests {
    use super::*;
    use entangle_mesh_tailscale::{AddressPolicy, TailnetState};

    async fn eventually(mut f: impl FnMut() -> bool) -> bool {
        for _ in 0..60 {
            if f() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    fn snapshot(state: TailnetState, n: u64) -> LivenessSnapshot {
        LivenessSnapshot {
            state: Some(state),
            since: None,
            transitions: n,
        }
    }

    // Needs a second loopback address (127.0.0.3): Linux routes all of 127/8
    // to `lo`; other systems configure only 127.0.0.1 by default.

    fn candidate(id_key: &IdentityKeyPair) -> TailscalePeer {
        TailscalePeer::new(
            *id_key.public().as_bytes(),
            "100.64.0.9:7002".parse().unwrap(),
        )
    }

    fn store_with(keys: &[(&IdentityKeyPair, TrustLevel)]) -> PeerStore {
        let store = PeerStore::new();
        for (k, trust) in keys {
            let id = PeerId::from_public_key_bytes(k.public().as_bytes());
            let mut p = entangle_peers::TrustedPeer::new(
                id,
                hex::encode(k.public().as_bytes()),
                "peer".into(),
            );
            p.trust = *trust;
            store.add(p).unwrap();
        }
        store
    }

    #[test]
    fn tailnet_only_peers_reach_the_worker_pool_when_trusted() {
        let (a, b, stranger, revoked) = (
            IdentityKeyPair::generate(),
            IdentityKeyPair::generate(),
            IdentityKeyPair::generate(),
            IdentityKeyPair::generate(),
        );
        let store = store_with(&[(&a, TrustLevel::Trusted), (&revoked, TrustLevel::Revoked)]);
        let pool = WorkerPool::new();
        let me = PeerId::from_public_key_bytes(b.public().as_bytes());
        let feeder = TailnetWorkers::new(pool.clone(), store, me);

        feeder.sync(&[candidate(&a), candidate(&stranger), candidate(&revoked)]);
        let live = pool.live(Duration::from_secs(60));
        let a_id = PeerId::from_public_key_bytes(a.public().as_bytes());
        assert_eq!(live.len(), 1, "only the trusted peer is placed: {live:?}");
        assert_eq!(live[0].peer_id, a_id);

        // A peer mDNS described keeps its hardware.
        let mut rich = live[0].clone();
        rich.cpu_cores = 32.0;
        pool.upsert(rich);
        feeder.sync(&[candidate(&a)]);
        assert_eq!(pool.live(Duration::from_secs(60))[0].cpu_cores, 32.0);

        // Leaving the tailnet drops what this feeder added, not other peers.
        let other = IdentityKeyPair::generate();
        let other_id = PeerId::from_public_key_bytes(other.public().as_bytes());
        pool.upsert(default_worker(other_id, "mdns".into()));
        feeder.clear();
        let ids: Vec<_> = pool.live(Duration::MAX).iter().map(|w| w.peer_id).collect();
        assert!(!ids.contains(&a_id), "the tailnet is gone: {ids:?}");
        assert!(ids.contains(&other_id), "an unrelated entry stays");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn leaving_active_forgets_every_tailnet_candidate() {
        let lo = |last: u8| std::net::IpAddr::from([127, 0, 0, last]);
        let cfg = |ip, port| MeshTailscaleConfig {
            acl_mode: AclMode::TrustTailnet,
            bind_ip: ip,
            port,
            address_policy: AddressPolicy::Any,
            ..MeshTailscaleConfig::default()
        };
        // B on 127.0.0.1:P; A probes port P (it listens on 127.0.0.3:P).
        let b = MeshTailscale::start(&IdentityKeyPair::generate(), cfg(lo(1), 0))
            .await
            .unwrap();
        let port = b.local_addr().port();
        let a = MeshTailscale::start(&IdentityKeyPair::generate(), cfg(lo(3), port))
            .await
            .unwrap();
        let json = r#"{"BackendState":"Running","Self":{"Online":true},
          "Peer":{"b":{"Online":true,"DNSName":"b.t.ts.net.","TailscaleIPs":["127.0.0.1"]}}}"#;
        let st = Arc::new(TailscaleStatus::parse(json).unwrap());

        let (state_tx, state_rx) = watch::channel(snapshot(TailnetState::Active, 1));
        let (_status_tx, status_rx) = watch::channel(Some(st));
        let task = tokio::spawn(run_discovery(
            a.clone(),
            state_rx,
            status_rx,
            Duration::from_secs(3600),
            None,
        ));
        assert!(
            eventually(|| a.candidates().len() == 1).await,
            "B discovered"
        );

        // `tailscale logout`: liveness confirms `stopped`.
        let stopped = TailnetState::Stopped {
            reason: "NeedsLogin".into(),
        };
        state_tx.send(snapshot(stopped, 2)).unwrap();
        assert!(
            eventually(|| a.candidates().is_empty()).await,
            "peers reachable only via mesh.tailscale must be marked unreachable: {:?}",
            a.candidates()
        );
        task.abort();
    }
}
