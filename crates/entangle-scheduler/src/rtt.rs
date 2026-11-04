//! Measured link latency for placement (spec §7.3: "link quality is
//! measured locally … between this node and each peer").
//!
//! The pool's feeders can only put a constant in `WorkerInfo::rtt_ms` (an
//! mDNS sighting or a tailnet candidate says nothing about latency). An
//! [`RttProber`] measures it: every round it sends each of up to
//! [`RttProber::max_per_round`] live workers — the ones probed longest ago
//! first — the probe `entangle diag mesh --probe` uses (a control frame
//! about a task that does not exist, which the worker answers
//! `UnknownTask` after authenticating the caller and executing nothing),
//! at most [`RttProber::concurrency`] at a time, each bounded by a timeout,
//! and records the round trip with
//! [`WorkerPool::set_measured_rtt`](crate::WorkerPool::set_measured_rtt).
//! A worker whose probe gets no answer has its measurement cleared, so its
//! advertised constant applies again. Nothing here is labelled by peer: the
//! prober records no metrics.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use entangle_types::peer_id::PeerId;
use parking_lot::Mutex;

use crate::dispatcher::DispatchError;
use crate::remote::RemoteDispatch;
use crate::wire::{ControlAction, ControlFrame};
use crate::work_unit::hash_canonical;
use crate::worker::WorkerPool;

/// Default interval between probing rounds.
pub const DEFAULT_PROBE_INTERVAL: Duration = Duration::from_secs(60);

/// Measures round-trip times to the pool's workers. See the module docs.
#[derive(Clone)]
pub struct RttProber {
    remote: Arc<RemoteDispatch>,
    pool: WorkerPool,
    ttl: Duration,
    /// Workers probed per round, at most.
    pub max_per_round: usize,
    /// Probes in flight at once, at most.
    pub concurrency: usize,
    /// How long one probe may take.
    pub timeout: Duration,
    last_probed: Arc<Mutex<HashMap<PeerId, Instant>>>,
}

impl std::fmt::Debug for RttProber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RttProber")
            .field("max_per_round", &self.max_per_round)
            .field("concurrency", &self.concurrency)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// What one probe found.
#[derive(Clone, Debug, PartialEq)]
pub enum ProbeResult {
    /// The worker answered after this long.
    Answered(Duration),
    /// No answer (unreachable, timed out); why.
    Failed(String),
}

impl RttProber {
    /// Probe `pool`'s live workers (those updated within `ttl`) through
    /// `remote`: 16 per round, 4 at a time, 2 s each.
    pub fn new(remote: Arc<RemoteDispatch>, pool: WorkerPool, ttl: Duration) -> Self {
        Self {
            remote,
            pool,
            ttl,
            max_per_round: 16,
            concurrency: 4,
            timeout: Duration::from_secs(2),
            last_probed: Arc::default(),
        }
    }

    /// One probe of `peer`: the round trip of a control frame about a task
    /// that does not exist. Any answer from the worker counts (even a
    /// refusal: it measured the path); only no answer is a failure.
    pub async fn probe(&self, peer: PeerId) -> ProbeResult {
        let frame = ControlFrame {
            task_id: *uuid::Uuid::new_v4().as_bytes(),
            action: ControlAction::SetPolicy {
                policy: Vec::new(),
                policy_hash: hash_canonical(&[]),
            },
        };
        let started = Instant::now();
        match self.remote.send_control(peer, frame, self.timeout).await {
            Ok(_) | Err(DispatchError::RemoteRejected { .. }) => {
                ProbeResult::Answered(started.elapsed())
            }
            Err(e) => ProbeResult::Failed(e.to_string()),
        }
    }

    /// One probing round (see the module docs). Returns how many workers
    /// answered.
    pub async fn round(&self) -> usize {
        let local = self.remote.local_peer_id();
        let mut peers: Vec<PeerId> = self
            .pool
            .live(self.ttl)
            .into_iter()
            .map(|w| w.peer_id)
            .filter(|p| *p != local)
            .collect();
        {
            let last = self.last_probed.lock();
            // Never-probed first, then the longest ago.
            peers.sort_by_key(|p| last.get(p).copied());
        }
        peers.truncate(self.max_per_round);
        let limit = Arc::new(tokio::sync::Semaphore::new(self.concurrency.max(1)));
        let mut set = tokio::task::JoinSet::new();
        for peer in peers {
            let this = self.clone();
            let limit = Arc::clone(&limit);
            set.spawn(async move {
                let _slot = limit.acquire_owned().await;
                (peer, this.probe(peer).await)
            });
        }
        let mut answered = 0;
        while let Some(joined) = set.join_next().await {
            let Ok((peer, result)) = joined else { continue };
            self.last_probed.lock().insert(peer, Instant::now());
            match result {
                ProbeResult::Answered(rtt) => {
                    answered += 1;
                    self.pool.set_measured_rtt(&peer, rtt);
                    tracing::debug!(%peer, rtt_ms = rtt.as_millis() as u64, "measured worker RTT");
                }
                ProbeResult::Failed(why) => {
                    self.pool.clear_measured_rtt(&peer);
                    tracing::debug!(%peer, error = %why, "worker RTT probe got no answer");
                }
            }
        }
        // Forget workers that left the pool (bounded by the pool).
        let live: std::collections::HashSet<PeerId> = self
            .pool
            .live(Duration::MAX)
            .into_iter()
            .map(|w| w.peer_id)
            .collect();
        self.last_probed.lock().retain(|p, _| live.contains(p));
        answered
    }

    /// Probe every `interval` until the task is dropped.
    pub async fn run(self, interval: Duration) {
        let mut tick = tokio::time::interval(interval.max(Duration::from_secs(1)));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            self.round().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{DialTarget, Link, LinkError, Outbound, StreamIo, TransportKind};
    use crate::wire::{encode_response, RemoteErrorCode, RemoteTaskResponse};
    use crate::{TransportRouter, WorkerInfo};
    use entangle_mesh_iroh::IrohPeer;

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// Answers every control frame `UnknownTask` after `delay[peer]`; a
    /// peer without a delay cannot be connected to.
    #[derive(Debug)]
    struct Delayed(HashMap<PeerId, Duration>);

    #[async_trait::async_trait]
    impl Link for Delayed {
        fn kind(&self) -> TransportKind {
            TransportKind::Iroh
        }
        fn target(&self, peer: &PeerId) -> Option<DialTarget> {
            let k = (0..=255u8)
                .map(key)
                .find(|k| PeerId::from_public_key_bytes(k) == *peer)?;
            Some(DialTarget::Iroh(IrohPeer::new(k, "127.0.0.1:9".parse().ok()?)))
        }
        async fn request(
            &self,
            target: &DialTarget,
            outbound: &Outbound<'_>,
        ) -> Result<Vec<u8>, LinkError> {
            let Some(delay) = self.0.get(&target.peer_id()) else {
                return Err(LinkError::Connect("refused".into()));
            };
            let _ = outbound.frame();
            tokio::time::sleep(*delay).await;
            Ok(encode_response(&RemoteTaskResponse::err(
                RemoteErrorCode::UnknownTask,
                "no such task",
            ))
            .expect("encode"))
        }
        async fn open_stream(&self, _target: &DialTarget) -> Result<StreamIo, LinkError> {
            Err(LinkError::Connect("no streams".into()))
        }
    }

    fn worker(peer: PeerId, rtt_ms: u32) -> WorkerInfo {
        WorkerInfo {
            peer_id: peer,
            display_name: "w".into(),
            cpu_cores: 1.0,
            memory_bytes: 0,
            gpu: None,
            npu: None,
            network_bandwidth_bps: 0,
            rtt_ms,
            load: 0.0,
            cost: 1.0,
        }
    }

    /// A probe round measures each reachable worker's round trip into the
    /// pool; an unreachable one keeps its advertised constant.
    #[tokio::test]
    async fn a_round_measures_reachable_workers_and_falls_back_for_the_rest() {
        let (near, far, dead) = (
            PeerId::from_public_key_bytes(&key(1)),
            PeerId::from_public_key_bytes(&key(2)),
            PeerId::from_public_key_bytes(&key(3)),
        );
        let link = Delayed(HashMap::from([
            (near, Duration::from_millis(5)),
            (far, Duration::from_millis(120)),
        ]));
        let router = TransportRouter::new(PeerId::from_public_key_bytes(&key(9)))
            .with_link(Arc::new(link));
        let pool = WorkerPool::new();
        for p in [near, far, dead] {
            pool.upsert(worker(p, 5));
        }
        let prober = RttProber::new(
            Arc::new(RemoteDispatch::with_router(Arc::new(router))),
            pool.clone(),
            Duration::from_secs(60),
        );
        assert_eq!(prober.round().await, 2);
        let rtt = |p: PeerId| {
            pool.live(Duration::MAX)
                .into_iter()
                .find(|w| w.peer_id == p)
                .map(|w| w.rtt_ms)
        };
        assert!(rtt(near).is_some_and(|ms| ms < 100), "{:?}", rtt(near));
        assert!(rtt(far).is_some_and(|ms| ms >= 120), "{:?}", rtt(far));
        assert_eq!(rtt(dead), Some(5), "no answer: the advertised constant stays");
        assert_eq!(pool.measured_rtt(&dead), None);

        // Bounded: one worker per round, the least recently probed first.
        let mut one = prober.clone();
        one.max_per_round = 1;
        pool.clear_measured_rtt(&near);
        one.round().await;
        let probed: Vec<_> = one.last_probed.lock().keys().copied().collect();
        assert_eq!(probed.len(), 3, "all three have been probed by now");
    }
}
