//! Worker advertisement and pool management.

use crate::placement::{choose_from, PlacementChoice, PlacementError};
use entangle_types::plugin_id::PluginId;
use entangle_types::{
    peer_id::PeerId,
    resource::{GpuRequirement, NpuRequirement, ResourceSpec},
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Hardware capability advertisement from a worker peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerInfo {
    /// Peer identifier.
    pub peer_id: PeerId,
    /// Human-readable display name for the node.
    pub display_name: String,
    /// Number of logical CPU cores available (fractional allowed).
    pub cpu_cores: f32,
    /// Memory capacity in bytes, including a known container limit.
    pub memory_bytes: u64,
    /// GPU capability, if present.
    pub gpu: Option<GpuRequirement>,
    /// NPU capability, if present.
    pub npu: Option<NpuRequirement>,
    /// Measured upstream bandwidth in bps (best estimate, updated on heartbeat).
    pub network_bandwidth_bps: u64,
    /// Round-trip latency to the local node in milliseconds.
    pub rtt_ms: u32,
    /// Current load: 0.0 = idle, 1.0 = saturated.
    pub load: f32,
    /// Wall-clock cost factor (e.g., 1.0 = local desktop, 5.0 = metered cell).
    pub cost: f32,
}

/// Reasons a [`WorkerInfo`] advertisement fails validation.
///
/// Advertisements arrive from untrusted sources (e.g. unauthenticated mDNS),
/// so numeric fields parsed off the wire may be `NaN`, infinite, or negative.
/// [`WorkerInfo::validate`] rejects such adverts before they can reach the
/// placement scorer.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum WorkerValidationError {
    /// `cpu_cores` was not a finite, non-negative number.
    #[error("cpu_cores must be finite and non-negative, got {0}")]
    CpuCores(f32),
    /// `cost` was not a finite, non-negative number.
    #[error("cost must be finite and non-negative, got {0}")]
    Cost(f32),
    /// `load` was not a finite number.
    #[error("load must be finite, got {0}")]
    Load(f32),
}

impl WorkerInfo {
    /// Validate that the advertised numeric fields are well-formed.
    ///
    /// `cpu_cores` and `cost` must be finite and non-negative; `load` must be
    /// finite. This is the gate that keeps poisoned adverts (`NaN`/`inf`,
    /// parsed from an unauthenticated mDNS packet) out of the pool and away
    /// from [`choose`](crate::placement::choose).
    pub fn validate(&self) -> Result<(), WorkerValidationError> {
        if !self.cpu_cores.is_finite() || self.cpu_cores < 0.0 {
            return Err(WorkerValidationError::CpuCores(self.cpu_cores));
        }
        if !self.cost.is_finite() || self.cost < 0.0 {
            return Err(WorkerValidationError::Cost(self.cost));
        }
        if !self.load.is_finite() {
            return Err(WorkerValidationError::Load(self.load));
        }
        Ok(())
    }
}

/// Worker pool with TTL-based liveness.
#[derive(Clone)]
pub struct WorkerPool {
    inner: Arc<RwLock<HashMap<PeerId, Observations>>>,
    /// Hard cap on the number of distinct workers retained. Prevents an
    /// unauthenticated peer from flooding the pool with fresh identities.
    max_workers: usize,
}

/// Hardware and loaded plugin inventory from an authenticated scheduler endpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerCapabilities {
    /// Resource capacities used by placement.
    pub worker: WorkerInfo,
    /// Exact loaded plugin versions this worker can run as one-shot work.
    pub plugins: HashSet<PluginId>,
    /// Additional adapters that run only as streaming tasks.
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub streaming_plugins: HashSet<PluginId>,
}

/// Shared only by dispatches using this observation (or the permanent local worker).
#[derive(Clone, Default)]
pub(crate) struct InFlight(Arc<AtomicUsize>);

impl InFlight {
    pub(crate) fn reserve(&self) -> Reservation {
        self.0.fetch_add(1, Ordering::Relaxed);
        Reservation(Arc::clone(&self.0))
    }
}

/// A running dispatch owns one reservation until its future finishes or is dropped.
pub(crate) struct Reservation(Arc<AtomicUsize>);

impl Drop for Reservation {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Default)]
struct Observations {
    // Separate from advertisement data: fresh self-reports must not erase a penalty.
    semantic_reputation: Option<f64>,
    in_flight: InFlight,
    discovered: Option<(WorkerInfo, Instant)>,
    authenticated: Option<(WorkerCapabilities, Instant)>,
}

impl Observations {
    fn live(
        &self,
        now: Instant,
        ttl: Duration,
        plugin: Option<(&PluginId, bool)>,
    ) -> Option<&WorkerInfo> {
        if let Some((report, seen)) = &self.authenticated {
            if now.duration_since(*seen) < ttl {
                return plugin
                    .is_none_or(|(id, streaming)| {
                        report.plugins.contains(id)
                            || (streaming && report.streaming_plugins.contains(id))
                    })
                    .then_some(&report.worker);
            }
        }
        self.discovered
            .as_ref()
            .filter(|(_, seen)| now.duration_since(*seen) < ttl)
            .map(|(worker, _)| worker)
    }
}

impl Default for WorkerPool {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            max_workers: Self::DEFAULT_MAX_WORKERS,
        }
    }
}

impl WorkerPool {
    /// Default cap on the number of distinct workers retained.
    pub const DEFAULT_MAX_WORKERS: usize = 4096;

    /// Create a new empty pool with the default [`Self::DEFAULT_MAX_WORKERS`] cap.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an empty pool with a custom `max_workers` cap.
    pub fn with_max_workers(max_workers: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            max_workers,
        }
    }

    /// Insert or refresh a worker, returning whether the pool was updated.
    ///
    /// Returns `false` (making no change) when either:
    /// - `info` fails [`WorkerInfo::validate`] (poisoned `NaN`/`inf`/negative
    ///   fields), or
    /// - inserting a **new** peer would exceed the pool's `max_workers` cap.
    ///
    /// Refreshing an already-known peer is always permitted, even at the cap.
    /// The TTL clock resets on every successful call.
    pub fn upsert(&self, info: WorkerInfo) -> bool {
        if info.validate().is_err() {
            return false;
        }
        self.record(info.peer_id, |entry| {
            entry.discovered = Some((info, Instant::now()))
        })
    }

    /// Record the authenticated worker's current plugin inventory and hardware.
    pub fn upsert_authenticated(&self, report: WorkerCapabilities) -> bool {
        if report.worker.validate().is_err() {
            return false;
        }
        self.record(report.worker.peer_id, |entry| {
            entry.authenticated = Some((report, Instant::now()))
        })
    }

    fn record(&self, peer: PeerId, update: impl FnOnce(&mut Observations)) -> bool {
        let mut workers = self.inner.write();
        if !workers.contains_key(&peer) && workers.len() >= self.max_workers {
            return false;
        }
        update(workers.entry(peer).or_default());
        true
    }

    pub(crate) fn observe_semantic(&self, peer: &PeerId, agreed: bool) {
        if let Some(entry) = self.inner.write().get_mut(peer) {
            let previous = entry.semantic_reputation.unwrap_or(1.0);
            entry.semantic_reputation = Some(0.9 * previous + 0.1 * f64::from(agreed));
        }
    }

    /// EWMA of this retained worker's semantic correctness observations.
    pub fn semantic_reputation(&self, peer: &PeerId) -> f64 {
        self.inner
            .read()
            .get(peer)
            .and_then(|entry| entry.semantic_reputation)
            .unwrap_or(1.0)
    }

    /// Remove a worker (peer revoked, network gone, etc.).
    pub fn remove(&self, peer_id: &PeerId) -> Option<WorkerInfo> {
        let old = self.inner.write().remove(peer_id)?;
        old.authenticated
            .map(|(report, _)| report.worker)
            .or_else(|| old.discovered.map(|(worker, _)| worker))
    }

    /// Forget a LAN sighting while retaining independent mesh observations.
    pub fn remove_discovered(&self, peer_id: &PeerId) {
        let mut workers = self.inner.write();
        if let Some(entry) = workers.get_mut(peer_id) {
            entry.discovered = None;
            if entry.authenticated.is_none() {
                workers.remove(peer_id);
            }
        }
    }

    /// Return all workers whose last update was within `ttl`.
    ///
    /// This is the **placement view**: [`choose`](crate::placement::choose)
    /// runs against this TTL-filtered slice, not the full set counted by
    /// [`WorkerPool::len`].
    pub fn live(&self, ttl: Duration) -> Vec<WorkerInfo> {
        let now = Instant::now();
        self.inner
            .read()
            .values()
            .filter_map(|entry| entry.live(now, ttl, None).cloned())
            .collect()
    }

    /// Score live eligible workers without cloning each advertisement.
    pub(crate) fn choose(
        &self,
        ttl: Duration,
        spec: &ResourceSpec,
        plugin: &PluginId,
        local: Option<(&WorkerInfo, &InFlight)>,
        eligible: impl Fn(&PeerId) -> bool,
    ) -> Result<(PlacementChoice, Reservation), PlacementError> {
        self.choose_for(ttl, spec, (plugin, false), local, eligible)
    }

    pub(crate) fn choose_stream(
        &self,
        ttl: Duration,
        spec: &ResourceSpec,
        plugin: &PluginId,
        eligible: impl Fn(&PeerId) -> bool,
    ) -> Result<(PlacementChoice, Reservation), PlacementError> {
        self.choose_for(ttl, spec, (plugin, true), None, eligible)
    }

    fn choose_for(
        &self,
        ttl: Duration,
        spec: &ResourceSpec,
        plugin: (&PluginId, bool),
        local: Option<(&WorkerInfo, &InFlight)>,
        eligible: impl Fn(&PeerId) -> bool,
    ) -> Result<(PlacementChoice, Reservation), PlacementError> {
        // Only one upgradable reader can select/reserve at once. Ordinary pool
        // readers remain independent and no lock is held during execution.
        let workers = self.inner.upgradable_read();
        let now = Instant::now();
        let candidates = workers
            .values()
            .filter_map(|entry| Some((entry.live(now, ttl, Some(plugin))?, &entry.in_flight)))
            .filter(|(worker, _)| local.is_none_or(|(own, _)| own.peer_id != worker.peer_id))
            .chain(local)
            .filter(|(info, _)| eligible(&info.peer_id))
            .map(|(info, counter)| (info, counter.0.load(Ordering::Relaxed), counter));
        let (choice, counter) = choose_from(candidates, spec)?;
        Ok((choice, counter.reserve()))
    }

    /// Number of workers currently retained, **including entries that have
    /// expired but not yet been pruned** by [`WorkerPool::remove_stale`].
    ///
    /// For the set eligible for placement, use [`WorkerPool::live`].
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Whether the pool holds no workers at all (expired or not).
    ///
    /// See [`WorkerPool::len`]; the placement view is [`WorkerPool::live`].
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }

    /// Drop every worker whose last update is older than `ttl` and return
    /// how many were removed.
    ///
    /// The maintenance loop in `entangled` calls this on a fixed interval
    /// so stale peers don't grow the pool unboundedly.
    pub fn remove_stale(&self, ttl: Duration) -> usize {
        let now = Instant::now();
        let mut guard = self.inner.write();
        let before = guard.len();
        guard.retain(|_, entry| entry.live(now, ttl, None).is_some());
        before - guard.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_peer(byte: u8) -> PeerId {
        PeerId::from_public_key_bytes(&[byte; 32])
    }

    fn make_worker(peer_id: PeerId) -> WorkerInfo {
        WorkerInfo {
            peer_id,
            display_name: "test-node".into(),
            cpu_cores: 4.0,
            memory_bytes: 8 * 1024 * 1024 * 1024,
            gpu: None,
            npu: None,
            network_bandwidth_bps: 1_000_000_000,
            rtt_ms: 1,
            load: 0.1,
            cost: 1.0,
        }
    }

    #[test]
    fn authenticated_inventory_controls_placement_across_lan_updates() {
        let pool = WorkerPool::new();
        let ttl = Duration::from_secs(60);
        let id = make_peer(1);
        let plugin: PluginId = "aabbccddeeff00112233445566778899/available@1.0.0"
            .parse()
            .unwrap();
        let missing: PluginId = "aabbccddeeff00112233445566778899/absent@1.0.0"
            .parse()
            .unwrap();
        let fits = |plugin| {
            pool.choose(ttl, &ResourceSpec::default(), plugin, None, |_| true)
                .is_ok()
        };

        let mut worker = make_worker(id);
        pool.upsert_authenticated(WorkerCapabilities {
            worker: worker.clone(),
            plugins: [plugin.clone()].into(),
            streaming_plugins: [missing.clone()].into(),
        });
        worker.memory_bytes = 0;
        pool.upsert(worker);
        assert!(fits(&plugin));
        assert!(!fits(&missing));
        assert!(pool
            .choose_stream(ttl, &ResourceSpec::default(), &missing, |_| true)
            .is_ok());
        assert!(pool.live(ttl)[0].memory_bytes > 0);

        pool.remove_discovered(&id);
        assert!(fits(&plugin));
        assert!(pool.remove(&id).is_some());
        assert!(!fits(&plugin));
    }

    #[test]
    fn dropping_a_reservation_after_expiry_cannot_release_a_new_workers_slot() {
        let pool = WorkerPool::new();
        let worker = make_worker(make_peer(1));
        let plugin: PluginId = "0123456789abcdef0123456789abcdef/demo@1.0.0"
            .parse()
            .unwrap();
        let reserve = || {
            pool.choose(
                Duration::from_secs(60),
                &ResourceSpec::default(),
                &plugin,
                None,
                |_| true,
            )
            .unwrap()
        };
        pool.upsert(worker.clone());
        let (_, expired) = reserve();
        assert_eq!(pool.remove_stale(Duration::ZERO), 1);
        pool.upsert(worker);
        let (new_choice, current) = reserve();
        drop(expired);
        let (busy, _) = reserve();
        assert!(busy.score < new_choice.score);
        drop(current);
        assert_eq!(reserve().0.score, new_choice.score);
    }

    #[test]
    fn pool_upsert_and_live_returns_recent_only() {
        let pool = WorkerPool::new();
        let peer = make_peer(1);
        pool.upsert(make_worker(peer));

        // Very generous TTL — worker should appear.
        let live = pool.live(Duration::from_secs(60));
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].peer_id, peer);
    }

    #[test]
    fn pool_remove_drops_worker() {
        let pool = WorkerPool::new();
        let peer = make_peer(2);
        pool.upsert(make_worker(peer));
        assert_eq!(pool.len(), 1);

        let removed = pool.remove(&peer);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().peer_id, peer);
        assert!(pool.is_empty());
    }

    #[test]
    fn remove_stale_drops_old_workers_returns_count() {
        let pool = WorkerPool::new();
        pool.upsert(make_worker(make_peer(10)));
        pool.upsert(make_worker(make_peer(11)));
        // Zero TTL = everything is stale.
        let removed = pool.remove_stale(Duration::from_nanos(0));
        assert_eq!(removed, 2);
        assert!(pool.is_empty());
    }

    #[test]
    fn remove_stale_keeps_fresh_workers() {
        let pool = WorkerPool::new();
        pool.upsert(make_worker(make_peer(12)));
        // Very generous TTL = nothing is stale.
        let removed = pool.remove_stale(Duration::from_secs(3600));
        assert_eq!(removed, 0);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn live_filters_by_ttl() {
        let pool = WorkerPool::new();
        let peer = make_peer(3);
        pool.upsert(make_worker(peer));

        // Zero TTL — nothing should be live.
        let live = pool.live(Duration::from_nanos(0));
        assert!(live.is_empty(), "zero-TTL should return no workers");

        // Long TTL — should appear.
        let live = pool.live(Duration::from_secs(3600));
        assert_eq!(live.len(), 1);
    }

    #[test]
    fn validate_flags_poisoned_numeric_fields() {
        assert!(make_worker(make_peer(1)).validate().is_ok());

        let mut nan_cpu = make_worker(make_peer(1));
        nan_cpu.cpu_cores = f32::NAN;
        assert!(matches!(
            nan_cpu.validate(),
            Err(WorkerValidationError::CpuCores(_))
        ));

        let mut neg_cpu = make_worker(make_peer(1));
        neg_cpu.cpu_cores = -1.0;
        assert!(matches!(
            neg_cpu.validate(),
            Err(WorkerValidationError::CpuCores(_))
        ));

        let mut inf_cost = make_worker(make_peer(1));
        inf_cost.cost = f32::INFINITY;
        assert!(matches!(
            inf_cost.validate(),
            Err(WorkerValidationError::Cost(_))
        ));

        let mut nan_load = make_worker(make_peer(1));
        nan_load.load = f32::NAN;
        assert!(matches!(
            nan_load.validate(),
            Err(WorkerValidationError::Load(_))
        ));
    }

    #[test]
    fn upsert_rejects_poisoned_worker() {
        let pool = WorkerPool::new();
        let mut poisoned = make_worker(make_peer(1));
        poisoned.cpu_cores = f32::NAN;
        assert!(
            !pool.upsert(poisoned),
            "NaN-cpu advert must be rejected by upsert"
        );
        assert!(pool.is_empty(), "rejected advert must not enter the pool");
    }

    #[test]
    fn upsert_enforces_max_workers_cap() {
        let pool = WorkerPool::with_max_workers(2);
        assert!(pool.upsert(make_worker(make_peer(1))));
        assert!(pool.upsert(make_worker(make_peer(2))));
        // A third *distinct* peer exceeds the cap and is refused.
        assert!(
            !pool.upsert(make_worker(make_peer(3))),
            "new peer beyond the cap must be rejected"
        );
        assert_eq!(pool.len(), 2);
        // Refreshing an already-known peer is still allowed at the cap.
        assert!(
            pool.upsert(make_worker(make_peer(1))),
            "refresh of a known peer must succeed even at the cap"
        );
        assert_eq!(pool.len(), 2);
    }

    /// Wire-format roundtrip: every `WorkerInfo` field survives JSON serde.
    ///
    /// `WorkerInfo` is the on-the-wire shape carried inside chitchat gossip
    /// (spec §6.4.1 / §7.2); breaking serde compatibility would silently
    /// drop fields on the receiver.
    #[test]
    fn worker_info_json_roundtrip_preserves_all_fields() {
        use entangle_types::resource::{GpuBackend, GpuRequirement, NpuRequirement};

        let original = WorkerInfo {
            peer_id: make_peer(0xAA),
            display_name: "gpu-node".into(),
            cpu_cores: 12.5,
            memory_bytes: 32 * 1024 * 1024 * 1024,
            gpu: Some(GpuRequirement {
                vram_min_bytes: 8 * 1024 * 1024 * 1024,
                backend: GpuBackend::Cuda,
            }),
            npu: Some(NpuRequirement {
                vendor: "apple".into(),
            }),
            network_bandwidth_bps: 10_000_000_000,
            rtt_ms: 12,
            load: 0.42,
            cost: 1.5,
        };
        let json = serde_json::to_string(&original).expect("serialise");
        let parsed: WorkerInfo = serde_json::from_str(&json).expect("deserialise");

        assert_eq!(parsed.peer_id, original.peer_id);
        assert_eq!(parsed.display_name, original.display_name);
        assert_eq!(parsed.cpu_cores, original.cpu_cores);
        assert_eq!(parsed.memory_bytes, original.memory_bytes);
        assert!(parsed.gpu.is_some());
        let gpu = parsed.gpu.unwrap();
        assert_eq!(gpu.vram_min_bytes, 8 * 1024 * 1024 * 1024);
        assert_eq!(gpu.backend, GpuBackend::Cuda);
        let npu = parsed.npu.expect("npu round-trip");
        assert_eq!(npu.vendor, "apple");
        assert_eq!(parsed.network_bandwidth_bps, original.network_bandwidth_bps);
        assert_eq!(parsed.rtt_ms, original.rtt_ms);
        assert!((parsed.load - original.load).abs() < f32::EPSILON);
        assert_eq!(parsed.cost, original.cost);
    }
}
