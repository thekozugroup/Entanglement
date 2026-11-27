//! Demand-driven updates of the existing local Tailscale status snapshot.

use super::{online_status, Mapping};
use entangle_mesh_tailscale::{MeshTailscale, TailnetStatus};
use entangle_types::peer_id::PeerId;
use std::{
    collections::BTreeSet,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{mpsc, watch},
    time::{self, Instant},
};

const COOLDOWN: Duration = Duration::from_secs(1);
const WAIT: Duration = Duration::from_secs(1);
const QUERY_TIMEOUT: Duration = Duration::from_millis(750);

#[derive(Debug)]
struct State {
    earliest: Instant,
    pending: Option<watch::Receiver<()>>,
}

pub(super) struct Requests {
    receive: mpsc::Receiver<watch::Sender<()>>,
    state: Arc<Mutex<State>>,
}

impl Requests {
    fn start_query(&self, done: &watch::Sender<()>, now: Instant) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        // The coordinator retains one receiver. Retire an abandoned request
        // under the same lock that a new waiter uses to join it.
        if done.receiver_count() <= 1 || now < state.earliest {
            state.pending = None;
            return false;
        }
        state.earliest = now + COOLDOWN;
        true
    }
}

/// The status query covers all mappings, so callers share one request across
/// peers. The stored receiver lets new callers join until the owner drops the
/// completion channel. Only the status owner advances the cooldown.
#[derive(Debug)]
pub(super) struct Demand {
    mapped: BTreeSet<PeerId>,
    send: mpsc::Sender<watch::Sender<()>>,
    state: Arc<Mutex<State>>,
}

impl Demand {
    pub fn channel(mappings: &[Mapping]) -> (Option<Self>, Option<Requests>) {
        if mappings.is_empty() {
            return (None, None);
        }
        let mapped = mappings
            .iter()
            .map(|mapping| PeerId::from_public_key_bytes(&mapping.public_key))
            .collect();
        let (send, receive) = mpsc::channel(1);
        let state = Arc::new(Mutex::new(State {
            earliest: Instant::now(),
            pending: None,
        }));
        (
            Some(Self {
                mapped,
                send,
                state: state.clone(),
            }),
            Some(Requests { receive, state }),
        )
    }

    pub fn is_mapped(&self, peer: &PeerId) -> bool {
        self.mapped.contains(peer)
    }

    fn join_or_start(&self, now: Instant) -> Option<watch::Receiver<()>> {
        let mut state = self.state.lock().ok()?;
        if let Some(reply) = state
            .pending
            .as_ref()
            .filter(|reply| matches!(reply.has_changed(), Ok(false)))
        {
            return Some(reply.clone());
        }
        if now < state.earliest {
            return None;
        }
        let (done, reply) = watch::channel(());
        self.send.try_send(done).ok()?;
        state.pending = Some(reply.clone());
        Some(reply)
    }

    pub async fn refresh(&self) {
        let Some(mut reply) = self.join_or_start(Instant::now()) else {
            return;
        };
        let _ = time::timeout(WAIT, reply.changed()).await;
    }
}

/// Run demand and periodic checks in the same owner, so two CLI invocations
/// cannot race to publish different snapshots. The periodic cadence is
/// independent of demand. Only periodic failures can force listener recovery.
pub(super) struct Updates {
    interval: Duration,
    periodic_at: Instant,
}

impl Updates {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            periodic_at: Instant::now() + interval,
        }
    }

    pub async fn next(
        &mut self,
        requests: &mut Option<Requests>,
        mesh: &MeshTailscale,
        bind: SocketAddr,
    ) -> (anyhow::Result<TailnetStatus>, Option<watch::Sender<()>>) {
        loop {
            let requested = if let Some(requests) = requests {
                tokio::select! {
                    biased;
                    _ = time::sleep_until(self.periodic_at) => None,
                    Some(done) = requests.receive.recv() => Some(done),
                }
            } else {
                time::sleep_until(self.periodic_at).await;
                None
            };
            let Some(done) = requested else {
                let result = online_status(mesh, bind).await.map(|(status, _)| status);
                self.periodic_at = Instant::now() + self.interval;
                return (result, None);
            };
            if !requests
                .as_ref()
                .is_some_and(|owner| owner.start_query(&done, Instant::now()))
            {
                continue;
            }
            if let Ok(Ok((status, _))) =
                time::timeout(QUERY_TIMEOUT, online_status(mesh, bind)).await
            {
                return (Ok(status), Some(done));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn requests_share_one_snapshot_and_cool_down() {
        let mapping = Mapping {
            node_id: "paired-worker".into(),
            public_key: [1; 32],
            port: 7443,
        };
        let (demand, requests) = Demand::channel(&[mapping]);
        let demand = demand.unwrap();
        let mut requests = requests.unwrap();
        let now = Instant::now();
        let first = demand.join_or_start(now).unwrap();
        let mut second = demand.join_or_start(now).unwrap();
        let complete = requests.receive.try_recv().unwrap();
        assert!(requests.receive.try_recv().is_err());
        assert_eq!(complete.receiver_count(), 3);
        // Simulate a delayed owner. Cooldown starts with the actual query,
        // even if callers already waited behind a periodic status check.
        let query_started = now + COOLDOWN * 2;
        assert!(requests.start_query(&complete, query_started));
        drop(first);
        complete.send_replace(());
        drop(complete);
        second.changed().await.unwrap();

        assert!(demand.join_or_start(query_started + COOLDOWN / 2).is_none());
        let mut third = demand.join_or_start(query_started + COOLDOWN).unwrap();
        assert!(requests.receive.try_recv().is_ok());
        assert!(
            third.changed().await.is_err(),
            "owner shutdown releases waiters"
        );
        drop(requests);
        assert!(demand.join_or_start(query_started + COOLDOWN * 2).is_none());
    }
}
