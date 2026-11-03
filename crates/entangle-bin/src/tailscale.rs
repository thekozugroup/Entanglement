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
    AclMode, LivenessHandle, LivenessSnapshot, MeshTailscale, MeshTailscaleConfig, PeerAllowlist,
    RequestHandler, TailscaleStatus,
};
use entangle_peers::{PeerStore, TrustLevel};
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
    let defaults = MeshTailscaleConfig::default();
    Ok(MeshTailscaleConfig {
        tailscale_cli: mesh.tailscale.tailscale_cli.clone(),
        acl_mode,
        allowlist: Some(Arc::new(StoreAllowlist(store))),
        port: mesh.tailscale.port,
        bind_ip: mesh.tailscale.bind_ip.unwrap_or(defaults.bind_ip),
        ..defaults
    })
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
) {
    loop {
        if state.borrow().is_active() {
            let snapshot = status.borrow().clone();
            if let Some(st) = snapshot {
                let found = t.discover(&st).await;
                tracing::debug!(candidates = found.len(), "mesh.tailscale discovery round");
            }
        } else {
            let dropped = t.clear_candidates();
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
    let discover = tokio::spawn(run_discovery(
        transport.clone(),
        liveness.state(),
        liveness.status(),
        DISCOVERY_INTERVAL,
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
