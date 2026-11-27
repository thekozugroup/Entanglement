//! Authenticated worker inventory polling and bounded placement-miss refresh.

use crate::remote::LanRoutes;
use async_trait::async_trait;
use entangle_scheduler::{
    worker::WorkerCapabilities, PeerAddressBook, PlacementRefresh, RemoteDispatch, WorkerPool,
};
use entangle_types::{
    peer_id::PeerId,
    task::{IntegrityPolicy, OneShotTask},
};
use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    sync::{watch, Notify},
    task::{JoinHandle, JoinSet},
    time::{self, Instant},
};

const PERIOD: Duration = Duration::from_secs(15);
const DEMAND_INTERVAL: Duration = Duration::from_secs(2);
const DEMAND_WAIT: Duration = Duration::from_millis(2500);
const DEMAND_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const BATCH_SIZE: usize = 8;

type Reply = watch::Receiver<Option<bool>>;

#[derive(Default)]
struct Pending {
    closed: bool,
    checking: usize,
    order: VecDeque<PeerId>,
    // Entries remain while a route check or query is active, so callers share both.
    replies: HashMap<PeerId, watch::Sender<Option<bool>>>,
}

struct Demand {
    pending: Mutex<Pending>,
    wake: Notify,
    progress: watch::Sender<()>,
}

impl Default for Demand {
    fn default() -> Self {
        Self {
            pending: Mutex::default(),
            wake: Notify::new(),
            progress: watch::channel(()).0,
        }
    }
}

impl Demand {
    fn reserve(&self, peers: Vec<PeerId>) -> (Vec<(PeerId, Reply)>, Vec<PeerId>) {
        let mut state = self.pending.lock().expect("capability demand lock");
        let mut replies = Vec::new();
        let mut checks = Vec::new();
        if !state.closed {
            for peer in peers {
                if let Some(reply) = state.replies.get(&peer) {
                    replies.push((peer, reply.subscribe()));
                } else if state.checking + state.order.len() < BATCH_SIZE {
                    let (send, receive) = watch::channel(None);
                    state.checking += 1;
                    state.replies.insert(peer, send);
                    replies.push((peer, receive));
                    checks.push(peer);
                }
            }
        }
        (replies, checks)
    }

    fn route_checked(&self, peer: PeerId, reachable: bool) {
        let mut state = self.pending.lock().expect("capability demand lock");
        if state.closed {
            return;
        }
        state.checking -= 1;
        if reachable {
            state.order.push_back(peer);
            self.wake.notify_one();
        } else if let Some(reply) = state.replies.remove(&peer) {
            reply.send_replace(Some(false));
            self.progress.send_replace(());
        }
    }

    fn take(&self) -> Vec<PeerId> {
        let mut state = self.pending.lock().expect("capability demand lock");
        let mut peers: Vec<_> = state.order.drain(..).collect();
        peers.retain(|peer| {
            if state.replies[peer].receiver_count() == 0 {
                state.replies.remove(peer);
                false
            } else {
                true
            }
        });
        peers
    }

    fn complete(&self, peer: PeerId, refreshed: bool) {
        let mut state = self.pending.lock().expect("capability demand lock");
        if let Some(reply) = state.replies.remove(&peer) {
            reply.send_replace(Some(refreshed));
            self.progress.send_replace(());
        }
    }
}

struct CloseDemand(Option<Arc<Demand>>);

impl Drop for CloseDemand {
    fn drop(&mut self) {
        if let Some(demand) = &self.0 {
            let mut state = demand.pending.lock().expect("capability demand lock");
            state.closed = true;
            state.order.clear();
            state.replies.clear();
            demand.progress.send_replace(());
        }
    }
}

struct Refresh {
    configured: Vec<PeerId>,
    cursor: AtomicUsize,
    addresses: Arc<dyn PeerAddressBook>,
    pool: WorkerPool,
    demand: Arc<Demand>,
}

#[async_trait]
impl PlacementRefresh for Refresh {
    async fn refresh(&self, task: &OneShotTask) -> bool {
        time::timeout(DEMAND_WAIT, self.refresh_configured(task))
            .await
            .unwrap_or(false)
    }
}

impl Refresh {
    async fn refresh_configured(&self, task: &OneShotTask) -> bool {
        let eligible = match &task.integrity {
            IntegrityPolicy::None => &self.configured,
            IntegrityPolicy::TrustedExecutor { allowlist } => allowlist,
            _ => return false,
        };
        if eligible.is_empty() {
            return false;
        }
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % eligible.len();
        let mut seen = BTreeSet::new();
        let candidates = eligible[start..]
            .iter()
            .chain(&eligible[..start])
            .copied()
            .filter(|peer| self.configured.binary_search(peer).is_ok() && seen.insert(*peer))
            .take(BATCH_SIZE)
            .collect();
        let progress = self.demand.progress.subscribe();
        let (replies, checks) = self.demand.reserve(candidates);
        if !checks.is_empty() {
            // Deduplicate disk-backed trust and address checks before queueing.
            // A cancelled request does not strand a slot for other callers.
            let addresses = self.addresses.clone();
            let demand = self.demand.clone();
            tokio::task::spawn_blocking(move || {
                for peer in checks {
                    demand.route_checked(peer, addresses.lookup(&peer).is_some());
                }
            });
        }
        wait_for_usable_report(&self.pool, task, replies, progress).await
    }
}

async fn wait_for_usable_report(
    pool: &WorkerPool,
    task: &OneShotTask,
    replies: Vec<(PeerId, Reply)>,
    mut progress: watch::Receiver<()>,
) -> bool {
    loop {
        let mut waiting = false;
        for (peer, reply) in &replies {
            match *reply.borrow() {
                Some(true)
                    if pool.fits_authenticated(
                        peer,
                        &task.plugin,
                        &task.resources,
                        DEMAND_WAIT,
                    ) =>
                {
                    return true;
                }
                None if reply.has_changed().is_ok() => waiting = true,
                _ => {}
            }
        }
        if !waiting || progress.changed().await.is_err() {
            return false;
        }
    }
}

/// Start the daemon's sole capability polling task. Local placement misses may
/// request an earlier pass over explicitly configured peers.
pub fn start(
    client: Arc<RemoteDispatch>,
    addresses: Arc<dyn PeerAddressBook>,
    mut configured: Vec<PeerId>,
    lan: Option<Arc<LanRoutes>>,
    pool: WorkerPool,
) -> (Option<Arc<dyn PlacementRefresh>>, JoinHandle<()>) {
    configured.sort_unstable();
    configured.dedup();
    let demand = (!configured.is_empty()).then(|| Arc::new(Demand::default()));
    let refresh = demand.as_ref().map(|demand| {
        Arc::new(Refresh {
            configured: configured.clone(),
            cursor: AtomicUsize::new(0),
            addresses,
            pool: pool.clone(),
            demand: demand.clone(),
        }) as Arc<dyn PlacementRefresh>
    });
    let task = tokio::spawn(poll(client, configured, lan, pool, CloseDemand(demand)));
    (refresh, task)
}

#[derive(Default)]
struct QueryState {
    version: u64,
    active: HashMap<PeerId, InFlight>,
}

#[derive(Default)]
struct InFlight {
    running: usize,
    demanding: bool,
    published: u64,
}

#[derive(Default)]
struct Queries(Mutex<QueryState>);

impl Queries {
    fn begin(&self, peer: PeerId, expedited: bool) -> Option<u64> {
        let mut state = self.0.lock().expect("capability query lock");
        state.version += 1;
        let version = state.version;
        let active = state.active.entry(peer).or_default();
        if !expedited && active.demanding {
            // A current demand already probes this peer.
            return None;
        }
        active.running += 1;
        active.demanding |= expedited;
        Some(version)
    }

    fn complete(
        &self,
        pool: &WorkerPool,
        peer: PeerId,
        version: u64,
        expedited: bool,
        report: Option<WorkerCapabilities>,
    ) -> bool {
        let mut state = self.0.lock().expect("capability query lock");
        let active = state.active.get_mut(&peer).expect("query started");
        let latest = if version >= active.published {
            if let Some(report) = report.filter(|report| report.worker.peer_id == peer) {
                let refreshed = pool.upsert_authenticated(report);
                if refreshed {
                    active.published = version;
                }
                refreshed
            } else {
                false
            }
        } else {
            // Preserve inventory already written by a newer overlapping query.
            report.is_some()
        };
        active.running -= 1;
        if expedited {
            active.demanding = false;
        }
        if active.running == 0 {
            state.active.remove(&peer);
        }
        latest
    }
}

async fn poll(
    client: Arc<RemoteDispatch>,
    configured: Vec<PeerId>,
    lan: Option<Arc<LanRoutes>>,
    pool: WorkerPool,
    demand: CloseDemand,
) {
    let queries = Arc::new(Queries::default());
    let periodic = poll_periodic(&client, configured, lan, &pool, &queries);
    let expedited = poll_demand(&client, &pool, &queries, demand.0.as_ref());
    // Both lanes are children of the daemon's single polling task, so closing
    // it cancels their bounded JoinSets together.
    tokio::join!(periodic, expedited);
}

async fn poll_periodic(
    client: &Arc<RemoteDispatch>,
    configured: Vec<PeerId>,
    lan: Option<Arc<LanRoutes>>,
    pool: &WorkerPool,
    queries: &Arc<Queries>,
) {
    let configured = configured.into_iter().collect::<BTreeSet<_>>();
    let mut previous = BTreeSet::new();
    let mut timer = time::interval(PERIOD);
    timer.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        let mut peers = configured.clone();
        if let Some(lan) = lan.clone() {
            peers.extend(
                tokio::task::spawn_blocking(move || lan.peer_ids())
                    .await
                    .unwrap_or_default(),
            );
        }
        // A LAN-only report no longer has a route after discovery removal.
        for retired in previous.difference(&peers) {
            pool.remove(retired);
        }
        probe(client, pool, queries, peers.iter().copied(), None).await;
        previous = peers;
    }
}

async fn poll_demand(
    client: &Arc<RemoteDispatch>,
    pool: &WorkerPool,
    queries: &Arc<Queries>,
    demand: Option<&Arc<Demand>>,
) {
    let Some(demand) = demand else {
        return;
    };
    let mut next = Instant::now();
    loop {
        demand.wake.notified().await;
        time::sleep_until(next).await;
        let peers = demand.take();
        if !peers.is_empty() {
            next = Instant::now() + DEMAND_INTERVAL;
            probe(client, pool, queries, peers, Some(demand)).await;
        }
    }
}

async fn probe(
    client: &Arc<RemoteDispatch>,
    pool: &WorkerPool,
    queries: &Arc<Queries>,
    peers: impl IntoIterator<Item = PeerId>,
    demand: Option<&Arc<Demand>>,
) {
    let mut probes = JoinSet::new();
    for peer in peers {
        if probes.len() == BATCH_SIZE {
            probes.join_next().await;
        }
        let expedited = demand.is_some();
        let Some(version) = queries.begin(peer, expedited) else {
            continue;
        };
        let client = client.clone();
        let pool = pool.clone();
        let queries = queries.clone();
        let demand = demand.cloned();
        probes.spawn(async move {
            let query = client.capabilities(peer);
            let result = if expedited {
                time::timeout(DEMAND_PROBE_TIMEOUT, query).await.ok()
            } else {
                Some(query.await)
            };
            let report = match result {
                Some(Ok(report)) => Some(report),
                Some(Err(err)) => {
                    tracing::debug!(%peer, error = %err, "worker capability query unavailable");
                    None
                }
                None => None,
            };
            let refreshed = queries.complete(&pool, peer, version, expedited, report);
            if let Some(demand) = demand {
                demand.complete(peer, refreshed);
            }
        });
    }
    probes.join_all().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use entangle_mesh_iroh::{IrohPeer, MeshConn, MeshIrohError, MeshTransport};
    use entangle_runtime::{Kernel, KernelConfig};
    use entangle_scheduler::{
        wire::encode_response, DispatchError, Dispatcher, PeerDirectory, RemoteTaskResponse,
        WorkerInfo,
    };
    use entangle_signing::Keyring;
    use std::net::SocketAddr;

    fn peer(byte: u8) -> PeerId {
        PeerId::from_public_key_bytes(&[byte; 32])
    }

    fn task() -> OneShotTask {
        OneShotTask::with_defaults(
            "0123456789abcdef0123456789abcdef/fixture@0.1.0"
                .parse()
                .unwrap(),
            Vec::new(),
        )
    }

    fn report(peer_id: PeerId, loaded: bool) -> WorkerCapabilities {
        WorkerCapabilities {
            worker: WorkerInfo {
                peer_id,
                display_name: "fixture".into(),
                cpu_cores: 1.0,
                memory_bytes: 1024,
                gpu: None,
                npu: None,
                network_bandwidth_bps: 0,
                rtt_ms: 1,
                load: 0.0,
                cost: 0.0,
            },
            plugins: loaded.then(|| task().plugin).into_iter().collect(),
            streaming_plugins: Default::default(),
        }
    }

    #[test]
    fn earlier_periodic_result_cannot_replace_newer_demand_inventory() {
        let queries = Queries::default();
        let worker = peer(1);
        let pool = WorkerPool::new();
        let task = task();
        let periodic = queries.begin(worker, false).unwrap();
        let expedited = queries.begin(worker, true).unwrap();
        assert!(queries.begin(worker, false).is_none());
        assert!(queries.complete(&pool, worker, expedited, true, Some(report(worker, true))));
        queries.complete(&pool, worker, periodic, false, Some(report(worker, false)));
        assert!(pool.fits_authenticated(&worker, &task.plugin, &task.resources, DEMAND_WAIT));
    }

    #[tokio::test]
    async fn overlapping_requests_share_route_checks_and_the_query() {
        let demand = Arc::new(Demand::default());
        let a = peer(1);
        let (mut first, checks) = demand.reserve(vec![a]);
        assert_eq!(checks, vec![a]);
        let (mut overlapping, checks) = demand.reserve(vec![a]);
        assert!(checks.is_empty());
        demand.route_checked(a, true);
        assert_eq!(demand.take(), vec![a]);
        let (mut active, checks) = demand.reserve(vec![a]);
        assert!(checks.is_empty());
        demand.complete(a, true);
        for replies in [&mut first, &mut overlapping, &mut active] {
            let (_, reply) = &mut replies[0];
            assert!(reply.changed().await.is_ok());
            assert_eq!(*reply.borrow(), Some(true));
        }
        assert!(demand.take().is_empty());
    }

    #[tokio::test]
    async fn demand_reserves_only_eight_waiting_and_skips_cancelled_waiters() {
        let demand = Arc::new(Demand::default());
        let peers: Vec<_> = (0..16).map(peer).collect();
        let (replies, checks) = demand.reserve(peers.clone());
        assert_eq!(checks, peers[..8]);
        drop(replies);
        for peer in checks {
            demand.route_checked(peer, true);
        }
        assert!(demand.take().is_empty());
        let (mut replies, checks) = demand.reserve(vec![peers[8]]);
        assert_eq!(checks, vec![peers[8]]);
        demand.route_checked(peers[8], false);
        assert!(replies[0].1.changed().await.is_ok());
        assert_eq!(*replies[0].1.borrow(), Some(false));
        assert!(demand.take().is_empty());
    }

    #[tokio::test]
    async fn usable_report_does_not_wait_for_an_earlier_silent_peer() {
        let demand = Arc::new(Demand::default());
        let slow = peer(1);
        let healthy = peer(2);
        let progress = demand.progress.subscribe();
        let (replies, checks) = demand.reserve(vec![slow, healthy]);
        assert_eq!(checks, [slow, healthy]);
        demand.route_checked(slow, true);
        demand.route_checked(healthy, true);
        assert_eq!(demand.take(), [slow, healthy]);
        let task = task();
        let pool = WorkerPool::new();
        assert!(pool.upsert_authenticated(report(healthy, true)));
        demand.complete(healthy, true);
        assert!(time::timeout(
            Duration::from_millis(500),
            wait_for_usable_report(&pool, &task, replies, progress),
        )
        .await
        .unwrap());
    }

    #[tokio::test]
    async fn stopped_poller_closes_existing_and_future_requests() {
        let demand = Arc::new(Demand::default());
        let guard = CloseDemand(Some(demand.clone()));
        let (mut replies, checks) = demand.reserve(vec![peer(1)]);
        assert_eq!(checks, [peer(1)]);
        drop(guard);
        assert!(replies[0].1.changed().await.is_err());
        let (future, checks) = demand.reserve(vec![peer(2)]);
        assert!(future.is_empty() && checks.is_empty());
    }

    #[derive(Debug, Default)]
    struct InventoryTransport {
        slow_started: Notify,
        healthy_started: Notify,
        healthy_queries: AtomicUsize,
    }

    #[async_trait]
    impl MeshTransport for InventoryTransport {
        fn local_peer_id(&self) -> PeerId {
            peer(0)
        }
        fn local_public_key(&self) -> [u8; 32] {
            [0; 32]
        }
        fn local_addrs(&self) -> Vec<SocketAddr> {
            Vec::new()
        }
        async fn connect(&self, _: &IrohPeer) -> Result<MeshConn, MeshIrohError> {
            unreachable!("fixture accepts capability requests only")
        }
        async fn request(&self, target: &IrohPeer, _: &[u8]) -> Result<Vec<u8>, MeshIrohError> {
            if target.peer_id == peer(1) {
                self.slow_started.notify_one();
                return std::future::pending().await;
            }
            assert_eq!(target.peer_id, peer(2));
            let previously_queried = self.healthy_queries.fetch_add(1, Ordering::Relaxed) > 0;
            self.healthy_started.notify_one();
            let payload = serde_json::to_vec(&report(peer(2), previously_queried)).unwrap();
            Ok(encode_response(&RemoteTaskResponse::ok(payload)).unwrap())
        }
        async fn accept(&self) -> Result<Option<MeshConn>, MeshIrohError> {
            Ok(None)
        }
        async fn shutdown(&self) {}
    }

    #[tokio::test]
    async fn demand_can_reach_a_healthy_peer_while_periodic_is_stalled() {
        let transport = Arc::new(InventoryTransport::default());
        let addresses = Arc::new(PeerDirectory::new());
        for id in [1, 2] {
            addresses.insert(IrohPeer::new([id; 32], "127.0.0.1:9000".parse().unwrap()));
        }
        let client = Arc::new(RemoteDispatch::new(transport.clone(), addresses.clone()));
        let pool = WorkerPool::new();
        let (refresh, poller) = start(
            client,
            addresses.clone(),
            vec![peer(1), peer(2)],
            None,
            pool,
        );
        let refresh = refresh.unwrap();
        time::timeout(Duration::from_secs(1), async {
            transport.slow_started.notified().await;
            transport.healthy_started.notified().await;
            let mut task = task();
            // This peer is configured but has no route or trust anymore.
            addresses.remove(&peer(1));
            task.integrity = IntegrityPolicy::TrustedExecutor {
                allowlist: vec![peer(1)],
            };
            assert!(!refresh.refresh(&task).await);
            // The stalled periodic query cannot hold up this healthy responder.
            task.integrity = IntegrityPolicy::TrustedExecutor {
                allowlist: vec![peer(2)],
            };
            assert!(refresh.refresh(&task).await);
            assert_eq!(transport.healthy_queries.load(Ordering::Relaxed), 2);
        })
        .await
        .expect("demand did not wait for the unrelated periodic timeout");
        poller.abort();
        let _ = poller.await;
    }

    #[derive(Default)]
    struct SilentRefresh(AtomicUsize);

    #[async_trait]
    impl PlacementRefresh for SilentRefresh {
        async fn refresh(&self, _: &OneShotTask) -> bool {
            self.0.fetch_add(1, Ordering::Relaxed);
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn preplacement_refresh_respects_empty_allowlist_and_task_deadline() {
        let pool = WorkerPool::new();
        let transport = Arc::new(InventoryTransport::default());
        let addresses = Arc::new(PeerDirectory::new());
        let kernel = Arc::new(Kernel::new(KernelConfig::default(), Keyring::new()).unwrap());
        let dispatcher = Dispatcher::new(pool, kernel, peer(0))
            .with_remote(Arc::new(RemoteDispatch::new(transport, addresses)));
        let refresh = SilentRefresh::default();

        let mut denied = task();
        denied.integrity = IntegrityPolicy::TrustedExecutor { allowlist: vec![] };
        denied.timeout_ms = 20;
        let error = dispatcher
            .dispatch_one_shot_with_refresh(denied, Some(&refresh))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("ENTANGLE-E0303"));
        assert_eq!(refresh.0.load(Ordering::Relaxed), 0);

        let mut task = task();
        task.resources.cpu_cores = 1.0;
        task.timeout_ms = 20;
        let outcome = time::timeout(
            Duration::from_millis(500),
            dispatcher.dispatch_one_shot_with_refresh(task, Some(&refresh)),
        )
        .await
        .unwrap();
        assert!(matches!(outcome, Err(DispatchError::Placement(_))));
        assert_eq!(refresh.0.load(Ordering::Relaxed), 1);
    }
}
