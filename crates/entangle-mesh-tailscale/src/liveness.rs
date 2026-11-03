//! Tailnet liveness polling (spec §6.1.1).
//!
//! [`LivenessMachine`] is the pure state machine (hysteresis, grace period,
//! cadence); [`spawn_liveness`] drives it from a [`StatusSource`] and a
//! [`Clock`] and publishes the confirmed state on a `tokio::sync::watch`
//! channel. One structured `tracing` event is emitted per *transition*, never
//! per poll.
//!
//! Rules implemented:
//! * a change must be seen on `confirmations` (2) consecutive polls before it
//!   fires, so a single blip is invisible;
//! * leaving `Active` additionally requires the non-active condition to have
//!   persisted for the `grace` period (30 s), tolerating a `tailscaled`
//!   restart or auto-update;
//! * while the confirmed state is `Uninstalled` and nothing is pending, the
//!   cadence drops from 5 s to 5 minutes.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::status::{StatusSource, TailnetState, TailscaleStatus};

/// Timing parameters of the liveness loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LivenessConfig {
    /// Normal poll interval (spec: 5 s).
    pub poll_interval: Duration,
    /// Poll interval while confirmed `Uninstalled` (spec: 5 minutes).
    pub uninstalled_interval: Duration,
    /// Consecutive polls a change must persist for (spec: 2).
    pub confirmations: u32,
    /// How long a non-active condition must persist before `Active` is left
    /// (spec: 30 s).
    pub grace: Duration,
}

impl Default for LivenessConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(5),
            uninstalled_interval: Duration::from_secs(300),
            confirmations: 2,
            grace: Duration::from_secs(30),
        }
    }
}

/// Injectable time source for the poll loop.
///
/// Production uses [`TokioClock`]; tests supply a virtual clock whose
/// `sleep` advances `now` instantly.
#[async_trait::async_trait]
pub trait Clock: Send + Sync {
    /// Monotonic time since an arbitrary epoch.
    fn now(&self) -> Duration;
    /// Sleep for `d` of this clock's time.
    async fn sleep(&self, d: Duration);
}

/// Real-time [`Clock`].
#[derive(Debug)]
pub struct TokioClock {
    epoch: Instant,
}

impl Default for TokioClock {
    fn default() -> Self {
        Self {
            epoch: Instant::now(),
        }
    }
}

#[async_trait::async_trait]
impl Clock for TokioClock {
    fn now(&self) -> Duration {
        self.epoch.elapsed()
    }
    async fn sleep(&self, d: Duration) {
        tokio::time::sleep(d).await;
    }
}

/// A confirmed state change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transition {
    /// Previous confirmed state (`None` for the very first observation).
    pub from: Option<TailnetState>,
    /// New confirmed state.
    pub to: TailnetState,
}

#[derive(Clone, Debug)]
struct Pending {
    state: TailnetState,
    count: u32,
    first_seen: Duration,
}

/// Pure hysteresis / grace / cadence state machine.
#[derive(Clone, Debug)]
pub struct LivenessMachine {
    cfg: LivenessConfig,
    current: Option<TailnetState>,
    pending: Option<Pending>,
}

impl LivenessMachine {
    /// New machine with no confirmed state yet.
    pub fn new(cfg: LivenessConfig) -> Self {
        Self {
            cfg,
            current: None,
            pending: None,
        }
    }

    /// The confirmed state, if any poll has happened.
    pub fn current(&self) -> Option<&TailnetState> {
        self.current.as_ref()
    }

    /// Feed one observation taken at `now`; returns a transition when one is
    /// confirmed. The very first observation is adopted immediately.
    pub fn observe(&mut self, now: Duration, obs: TailnetState) -> Option<Transition> {
        let Some(cur) = self.current.clone() else {
            self.current = Some(obs.clone());
            return Some(Transition {
                from: None,
                to: obs,
            });
        };
        if cur == obs {
            self.pending = None;
            return None;
        }
        let leaving_active = cur == TailnetState::Active;
        match &mut self.pending {
            Some(p) if p.state == obs => p.count += 1,
            // While leaving Active the grace clock keeps running even if the
            // flavour of "not active" changes (e.g. stopped -> uninstalled).
            Some(p) if leaving_active => {
                p.state = obs;
                p.count = 1;
            }
            _ => {
                self.pending = Some(Pending {
                    state: obs,
                    count: 1,
                    first_seen: now,
                })
            }
        }
        let p = self.pending.as_ref()?;
        let graced = !leaving_active || now.saturating_sub(p.first_seen) >= self.cfg.grace;
        if p.count >= self.cfg.confirmations && graced {
            let to = p.state.clone();
            self.pending = None;
            self.current = Some(to.clone());
            return Some(Transition {
                from: Some(cur),
                to,
            });
        }
        None
    }

    /// How long to wait before the next poll.
    pub fn next_delay(&self) -> Duration {
        if self.pending.is_none() && self.current == Some(TailnetState::Uninstalled) {
            self.cfg.uninstalled_interval
        } else {
            self.cfg.poll_interval
        }
    }
}

/// What the watch channel carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LivenessSnapshot {
    /// Confirmed state; `None` until the first poll completes.
    pub state: Option<TailnetState>,
    /// Wall-clock time of the last transition.
    pub since: Option<SystemTime>,
    /// Number of confirmed transitions so far (the first poll counts).
    pub transitions: u64,
}

impl LivenessSnapshot {
    /// Whether the tailnet is confirmed active.
    pub fn is_active(&self) -> bool {
        self.state == Some(TailnetState::Active)
    }
}

/// Handle to a running liveness poller.
#[derive(Debug)]
pub struct LivenessHandle {
    state_rx: watch::Receiver<LivenessSnapshot>,
    status_rx: watch::Receiver<Option<Arc<TailscaleStatus>>>,
    task: JoinHandle<()>,
}

impl LivenessHandle {
    /// Subscribe to confirmed-state changes.
    pub fn state(&self) -> watch::Receiver<LivenessSnapshot> {
        self.state_rx.clone()
    }

    /// Subscribe to the most recent parsed status (updated every poll).
    pub fn status(&self) -> watch::Receiver<Option<Arc<TailscaleStatus>>> {
        self.status_rx.clone()
    }

    /// Stop the poller.
    pub fn shutdown(&self) {
        self.task.abort();
    }
}

impl Drop for LivenessHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn emit_transition(t: &Transition, at: SystemTime) {
    let from = t.from.as_ref().map_or("unknown", TailnetState::label);
    let reason = t.to.reason().unwrap_or("");
    match &t.to {
        TailnetState::Active => info!(
            target: "entangle::mesh::tailscale",
            from, to = "active", since_unix = unix_secs(at),
            "mesh.tailscale state transition"
        ),
        TailnetState::Stopped { .. } => warn!(
            target: "entangle::mesh::tailscale",
            from, to = "stopped", reason, since_unix = unix_secs(at),
            "mesh.tailscale state transition: peers reachable only via tailscale are unreachable"
        ),
        TailnetState::Uninstalled => warn!(
            target: "entangle::mesh::tailscale",
            from, to = "uninstalled", since_unix = unix_secs(at),
            hint = "run `entangle config set mesh.tailscale.enabled false` to drop the transport",
            "mesh.tailscale state transition: tailscale not installed, polling every 5 minutes"
        ),
    }
}

/// Start the liveness loop on the current tokio runtime.
pub fn spawn_liveness(
    source: Arc<dyn StatusSource>,
    clock: Arc<dyn Clock>,
    cfg: LivenessConfig,
) -> LivenessHandle {
    let (state_tx, state_rx) = watch::channel(LivenessSnapshot {
        state: None,
        since: None,
        transitions: 0,
    });
    let (status_tx, status_rx) = watch::channel(None);
    let task = tokio::spawn(async move {
        let mut machine = LivenessMachine::new(cfg);
        let mut transitions = 0u64;
        loop {
            let obs = source.observe().await;
            if let Some(status) = obs.status {
                let _ = status_tx.send(Some(Arc::new(status)));
            }
            if let Some(t) = machine.observe(clock.now(), obs.state) {
                transitions += 1;
                let at = SystemTime::now();
                emit_transition(&t, at);
                let _ = state_tx.send(LivenessSnapshot {
                    state: Some(t.to),
                    since: Some(at),
                    transitions,
                });
            }
            clock.sleep(machine.next_delay()).await;
        }
    });
    LivenessHandle {
        state_rx,
        status_rx,
        task,
    }
}
