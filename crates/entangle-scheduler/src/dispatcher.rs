//! Local dispatcher (Phase 1: in-process only).
//!
//! Phase 2 will add cross-node dispatch via Iroh streams with biscuit token verification.

use crate::{
    placement::{choose, PlacementChoice, PlacementError},
    worker::WorkerPool,
};
use entangle_runtime::Kernel;
use entangle_types::{peer_id::PeerId, task::OneShotTask};
use std::sync::Arc;
use std::time::Duration;

/// Errors that can arise during task dispatch.
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    /// Placement failed to find a suitable worker.
    #[error("placement: {0}")]
    Placement(#[from] PlacementError),
    /// The local kernel returned an error during invocation.
    #[error("local kernel error: {0}")]
    Runtime(#[from] entangle_runtime::RuntimeError),
    /// Cross-node dispatch is not yet implemented (Phase 2).
    ///
    /// Carries the chosen peer so callers can surface a useful message
    /// without re-running placement.
    #[error(
        "ENTANGLE-E0400: remote dispatch not implemented yet (Phase 2); \
         placement chose peer {peer}"
    )]
    RemoteNotImplemented {
        /// The peer placement chose; left unreached in Phase 1.
        peer: PeerId,
    },
}

/// Combines a placement decision with the task output bytes.
#[derive(Clone, Debug)]
pub struct DispatchResult {
    /// The placement decision that was made.
    pub chosen: PlacementChoice,
    /// Raw output bytes returned by the plugin.
    pub output: Vec<u8>,
}

/// In-process task dispatcher backed by the local [`Kernel`].
#[derive(Clone)]
pub struct Dispatcher {
    workers: WorkerPool,
    kernel: Arc<Kernel>,
    /// Local peer id — if placement chooses this peer, run in-process.
    local_peer_id: PeerId,
    /// TTL for considering a worker live.
    pub worker_ttl: Duration,
    /// When true, refuse to silently fall back to local execution when
    /// placement chooses a remote peer; instead, return
    /// [`DispatchError::RemoteNotImplemented`].
    ///
    /// Phase 1 default is `false` for backwards compatibility with the
    /// single-host demo; Phase 2 will flip this to `true` once cross-node
    /// dispatch is wired.
    pub strict_remote: bool,
}

impl Dispatcher {
    /// Create a new dispatcher.
    pub fn new(workers: WorkerPool, kernel: Arc<Kernel>, local_peer_id: PeerId) -> Self {
        Self {
            workers,
            kernel,
            local_peer_id,
            worker_ttl: Duration::from_secs(60),
            strict_remote: false,
        }
    }

    /// Enable strict remote enforcement.
    ///
    /// In strict mode the dispatcher returns
    /// [`DispatchError::RemoteNotImplemented`] when placement chooses a
    /// non-local peer, instead of silently re-running on the local kernel.
    pub fn with_strict_remote(mut self, strict: bool) -> Self {
        self.strict_remote = strict;
        self
    }

    /// Dispatch a [`OneShotTask`]: place → run → return output.
    ///
    /// Phase 1: only LOCAL dispatch is wired. If placement chooses a remote
    /// peer and `strict_remote` is `false`, execution falls back to the
    /// local kernel with a warning logged; otherwise [`DispatchError::RemoteNotImplemented`]
    /// is returned.
    pub async fn dispatch_one_shot(
        &self,
        task: OneShotTask,
    ) -> Result<DispatchResult, DispatchError> {
        let live = self.workers.live(self.worker_ttl);

        let chosen = choose(&live, &task.resources).or_else(|e| {
            match e {
                // No live workers and no resources required → use local kernel directly.
                PlacementError::NoWorkers
                    if task.resources.cpu_cores == 0.0 && task.resources.memory_bytes == 0 =>
                {
                    Ok(PlacementChoice {
                        peer_id: self.local_peer_id,
                        score: 0.0,
                        reason: "no workers — falling back to local".into(),
                    })
                }
                _ => Err(e),
            }
        })?;

        if chosen.peer_id != self.local_peer_id {
            if self.strict_remote {
                return Err(DispatchError::RemoteNotImplemented {
                    peer: chosen.peer_id,
                });
            }
            tracing::warn!(
                ?chosen,
                "Phase 1 stub: remote dispatch not implemented; falling back to local"
            );
        }

        let output = self
            .kernel
            .invoke(&task.plugin, &task.input, task.timeout_ms)
            .await?;

        Ok(DispatchResult { chosen, output })
    }
}
