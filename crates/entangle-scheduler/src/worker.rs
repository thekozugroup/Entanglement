//! Worker advertisement and pool management.

use entangle_types::{
    peer_id::PeerId,
    resource::{GpuRequirement, NpuRequirement},
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    /// Total host memory in bytes.
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

/// Worker pool with TTL-based liveness.
#[derive(Clone, Default)]
pub struct WorkerPool {
    inner: Arc<RwLock<HashMap<PeerId, (WorkerInfo, Instant)>>>,
}

impl WorkerPool {
    /// Create a new empty pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert/refresh a worker. The TTL clock resets on every call.
    pub fn upsert(&self, info: WorkerInfo) {
        self.inner
            .write()
            .insert(info.peer_id, (info, Instant::now()));
    }

    /// Remove a worker (peer revoked, network gone, etc.).
    pub fn remove(&self, peer_id: &PeerId) -> Option<WorkerInfo> {
        self.inner.write().remove(peer_id).map(|(info, _)| info)
    }

    /// Return all workers whose last update was within `ttl`.
    pub fn live(&self, ttl: Duration) -> Vec<WorkerInfo> {
        let now = Instant::now();
        self.inner
            .read()
            .values()
            .filter(|(_, ts)| now.duration_since(*ts) < ttl)
            .map(|(info, _)| info.clone())
            .collect()
    }

    /// Number of workers in the pool (including expired).
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
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
}
