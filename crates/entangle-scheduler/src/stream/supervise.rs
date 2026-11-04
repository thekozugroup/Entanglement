//! Streaming retry (spec §7.1 `StreamingTask.retry`: "retries restart from
//! `initial_inputs` only") and preempt-and-reassign.
//!
//! A [`SupervisedStream`] runs one stream over a list of candidate
//! executors. When an attempt fails in a way that says nothing about the
//! task — the connection or the executor was lost (`Transport`,
//! `PeerLost`), the executor could not be reached when opening, or the
//! scheduler preempted a stall to reassign it
//! ([`StallReaction::PreemptAndReassign`](super::StallReaction)) — the
//! stream is started again **from the task's initial input** on the next
//! candidate, as a new stream: a fresh task id, and a fresh per-attempt
//! capability token minted for its `Open`. Everything else (a plugin
//! error, a policy or capability refusal, a bad signature, a timeout, a
//! plain cancel or preemption) is final, as for one-shot tasks
//! ([`crate::retry`]).
//!
//! # Restarting after chunks were delivered
//!
//! A stream that fails **before the consumer received any chunk** is
//! restarted transparently. One that already delivered chunks is restarted
//! only when the task opts in (`StreamingTask::restart_after_delivery`):
//! a restart cannot resume where the old executor stopped (its output is
//! not reproducible in general), so the new attempt produces the whole
//! output again from sequence 0. Every chunk carries the **epoch** of the
//! attempt that produced it ([`SupervisedChunk::epoch`]); the epoch goes up
//! by one at each restart after a delivery, so a consumer that sees a new
//! epoch knows that the chunks of the previous epoch are superseded — it
//! discards what it already has (or skips the first chunks of the new
//! epoch, if the output is deterministic) instead of appending duplicates.
//!
//! Attempts are bounded by the task's `retry` policy (`max_attempts`,
//! backoff) and its deadline: no attempt starts after `timeout_ms` from the
//! first, and each gets the time that is left.
//!
//! A supervised stream carries **only its initial input** — the input the
//! spec says a retry restarts from: each attempt's input is finished as
//! soon as it is opened. A stream that needs further input (more turns)
//! uses a bare [`StreamHandle`], which is never restarted.

use std::sync::Arc;
use std::time::{Duration, Instant};

use entangle_types::peer_id::PeerId;
use entangle_types::task::StreamingTask;

use super::driver::{StreamHandle, StreamOptions, SubmitterReport};
use super::error::StreamError;
use super::submitter::{ChunkPoll, EndSummary, VerifiedChunk};
use crate::retry::RetryCause;
use crate::transport::TransportRouter;

/// Opens one attempt of a stream on one executor.
#[async_trait::async_trait]
pub trait StreamOpener: Send + Sync {
    /// Open `task` on `executor` and start streaming.
    async fn open(
        &self,
        executor: PeerId,
        task: &StreamingTask,
        options: StreamOptions,
    ) -> Result<StreamHandle, StreamError>;
}

#[async_trait::async_trait]
impl StreamOpener for TransportRouter {
    async fn open(
        &self,
        executor: PeerId,
        task: &StreamingTask,
        options: StreamOptions,
    ) -> Result<StreamHandle, StreamError> {
        self.open_stream(executor, task, options).await
    }
}

/// One verified chunk of a supervised stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisedChunk {
    /// The attempt epoch that produced it (0 until a restart after a
    /// delivery). A chunk of a higher epoch supersedes every chunk of the
    /// lower ones.
    pub epoch: u32,
    /// The executor that produced (and signed) it.
    pub executor: PeerId,
    /// The chunk, its sequence number counted within its epoch.
    pub chunk: VerifiedChunk,
}

/// What [`SupervisedStream::next`] has for the consumer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SupervisedPoll {
    /// The next verified chunk.
    Chunk(SupervisedChunk),
    /// The stream ended normally: `end` covers the chunks of `epoch`.
    Ended {
        /// The epoch that completed.
        epoch: u32,
        /// Its executor.
        executor: PeerId,
        /// The verified end.
        end: EndSummary,
    },
    /// The stream failed and is not (or no longer) restarted.
    Closed(StreamError),
}

/// One attempt of a supervised stream, for audit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamAttempt {
    /// Who ran it.
    pub executor: PeerId,
    /// Its task id (fresh for every attempt after the first).
    pub task_id: entangle_types::task::TaskId,
    /// Its epoch.
    pub epoch: u32,
    /// Why it was started again after it, if it was.
    pub restarted_because: Option<RetryCause>,
    /// Why it ended, if it failed.
    pub error: Option<String>,
}

/// A stream restarted on other executors as the task's retry policy
/// allows. See the module docs.
pub struct SupervisedStream {
    opener: Arc<dyn StreamOpener>,
    task: StreamingTask,
    candidates: Vec<PeerId>,
    options: StreamOptions,
    handle: Option<StreamHandle>,
    executor: PeerId,
    epoch: u32,
    delivered: u64,
    started: Instant,
    deadline: Instant,
    attempts: Vec<StreamAttempt>,
    terminal: Option<SupervisedPoll>,
}

impl std::fmt::Debug for SupervisedStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SupervisedStream")
            .field("task", &self.task.id)
            .field("executor", &self.executor)
            .field("epoch", &self.epoch)
            .field("attempts", &self.attempts.len())
            .finish()
    }
}

impl SupervisedStream {
    /// Open `task` on the first of `candidates` that accepts it (moving on
    /// only past executors that cannot be reached, within the task's retry
    /// policy) and supervise it.
    pub async fn open(
        opener: Arc<dyn StreamOpener>,
        task: StreamingTask,
        candidates: Vec<PeerId>,
        options: StreamOptions,
    ) -> Result<Self, StreamError> {
        let first = *candidates.first().ok_or_else(|| StreamError::InvalidTask {
            field: "executor",
            reason: "no candidate executor to open the stream on".into(),
        })?;
        let started = Instant::now();
        let mut this = Self {
            opener,
            deadline: started + Duration::from_millis(task.timeout_ms),
            task,
            candidates,
            options,
            handle: None,
            executor: first,
            epoch: 0,
            delivered: 0,
            started,
            attempts: Vec::new(),
            terminal: None,
        };
        match this.start_attempt(None).await {
            Ok(()) => Ok(this),
            Err(e) => Err(e),
        }
    }

    /// The executor of the current attempt.
    pub const fn executor(&self) -> PeerId {
        self.executor
    }

    /// The current epoch.
    pub const fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Every attempt so far.
    pub fn attempts(&self) -> &[StreamAttempt] {
        &self.attempts
    }

    /// The next chunk, or the stream's end. Restarts the stream on another
    /// executor as the module docs describe.
    pub async fn next(&mut self) -> SupervisedPoll {
        loop {
            if let Some(done) = &self.terminal {
                return done.clone();
            }
            let Some(handle) = self.handle.as_mut() else {
                let done = SupervisedPoll::Closed(StreamError::Closed(super::Reason::Internal));
                self.terminal = Some(done.clone());
                return done;
            };
            match handle.next().await {
                ChunkPoll::Chunk(chunk) => {
                    self.delivered += 1;
                    return SupervisedPoll::Chunk(SupervisedChunk {
                        epoch: self.epoch,
                        executor: self.executor,
                        chunk,
                    });
                }
                ChunkPoll::Ended(end) => {
                    let done = SupervisedPoll::Ended {
                        epoch: self.epoch,
                        executor: self.executor,
                        end,
                    };
                    self.terminal = Some(done.clone());
                    return done;
                }
                ChunkPoll::Pending => continue,
                ChunkPoll::Closed(error) => {
                    if let Some(last) = self.attempts.last_mut() {
                        last.error = Some(error.to_string());
                    }
                    let cause = restart_cause(&error);
                    let refused = match cause {
                        None => Some("the failure is final"),
                        Some(_) if self.delivered > 0 && !self.task.restart_after_delivery => {
                            Some("chunks were delivered and the task does not opt in to restarts")
                        }
                        Some(_) => None,
                    };
                    if let Some(why) = refused {
                        tracing::debug!(task = %self.task.id, error = %error, why, "stream not restarted");
                        let done = SupervisedPoll::Closed(self.exhausted(error));
                        self.terminal = Some(done.clone());
                        return done;
                    }
                    let restarted_after_delivery = self.delivered > 0;
                    let previous = self.handle.take();
                    if let Some(old) = previous {
                        // Collect the old attempt (its executor is already
                        // gone, or was cancelled).
                        let _ = old.finish().await;
                    }
                    if let Err(e) = self.start_attempt(cause.map(|c| (c, error.clone()))).await {
                        let done = SupervisedPoll::Closed(e);
                        self.terminal = Some(done.clone());
                        return done;
                    }
                    if restarted_after_delivery {
                        self.epoch += 1;
                        if let Some(last) = self.attempts.last_mut() {
                            last.epoch = self.epoch;
                        }
                    }
                    self.delivered = 0;
                }
            }
        }
    }

    /// Cancel the current attempt and return its report (`None` once the
    /// stream is over).
    pub async fn finish(mut self) -> Option<SubmitterReport> {
        match self.handle.take() {
            Some(handle) => Some(handle.finish().await),
            None => None,
        }
    }

    /// `error`, or — when more than one attempt was made — the fact that
    /// they ran out, with `error` as the last one's.
    fn exhausted(&self, error: StreamError) -> StreamError {
        if self.attempts.len() > 1 {
            StreamError::AttemptsExhausted {
                attempts: u32::try_from(self.attempts.len()).unwrap_or(u32::MAX),
                last: Box::new(error),
            }
        } else {
            error
        }
    }

    /// Start the next attempt: the first one (`after = None`), or a restart
    /// after `after` failed the previous one. Moves past executors that
    /// cannot be reached while attempts and time are left.
    async fn start_attempt(
        &mut self,
        mut after: Option<(RetryCause, StreamError)>,
    ) -> Result<(), StreamError> {
        let policy = self.task.retry;
        loop {
            let tried: Vec<PeerId> = self.attempts.iter().map(|a| a.executor).collect();
            let target = match &after {
                None => Some(self.executor),
                Some((cause, _)) => {
                    let fresh = self.candidates.iter().copied().find(|p| !tried.contains(p));
                    fresh.or_else(|| {
                        (cause.may_return_to_same_worker() && !tried.is_empty())
                            .then_some(self.executor)
                    })
                }
            };
            if let Some((cause, error)) = &after {
                let made = self.attempts.len();
                let now = Instant::now();
                let Some(target) =
                    target.filter(|_| made < usize::from(policy.attempts()) && now < self.deadline)
                else {
                    return Err(self.exhausted(error.clone()));
                };
                if let Some(last) = self.attempts.last_mut() {
                    last.restarted_because = Some(*cause);
                }
                if let Some(reg) = &self.options.metrics {
                    entangle_observability::catalog::scheduler_retry(reg, "stream", cause.label());
                }
                let wait = policy
                    .backoff(u32::try_from(made).unwrap_or(u32::MAX))
                    .min(self.deadline.saturating_duration_since(now));
                tracing::info!(
                    task = %self.task.id,
                    failed = %self.executor,
                    next = %target,
                    cause = cause.label(),
                    wait_ms = wait.as_millis() as u64,
                    "restarting the stream from its initial input"
                );
                tokio::time::sleep(wait).await;
                if Instant::now() >= self.deadline {
                    return Err(self.exhausted(error.clone()));
                }
                self.executor = target;
            }
            // Every attempt after the first is a new stream: a fresh id
            // (and so a fresh per-attempt capability token, minted for its
            // own `Open`), and the time left.
            let mut attempt = self.task.clone();
            if !self.attempts.is_empty() {
                attempt.id = uuid::Uuid::new_v4();
                attempt.timeout_ms = u64::try_from(
                    self.deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis(),
                )
                .unwrap_or(u64::MAX)
                .max(1);
            }
            self.attempts.push(StreamAttempt {
                executor: self.executor,
                task_id: attempt.id,
                epoch: self.epoch,
                restarted_because: None,
                error: None,
            });
            match self
                .opener
                .open(self.executor, &attempt, self.options.clone())
                .await
            {
                Ok(mut handle) => {
                    // A supervised stream carries its initial input only
                    // (a restart could not replay more): tell the executor
                    // no more follows. A failure here shows in `next`.
                    let _ = handle.finish_input().await;
                    self.handle = Some(handle);
                    return Ok(());
                }
                Err(e) => {
                    if let Some(last) = self.attempts.last_mut() {
                        last.error = Some(e.to_string());
                    }
                    // Opening failed: only an unreachable executor is moved
                    // past.
                    match open_failure_cause(&e) {
                        Some(cause) => after = Some((cause, e)),
                        None => return Err(self.exhausted(e)),
                    }
                }
            }
        }
    }

    /// How long the stream has been running.
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

/// Why a running stream that failed with `error` may be restarted (see the
/// module docs).
pub fn restart_cause(error: &StreamError) -> Option<RetryCause> {
    match error {
        StreamError::Transport(_) | StreamError::PeerLost { .. } => Some(RetryCause::LostAfterSend),
        StreamError::Preempted { reassign: true, .. } => Some(RetryCause::Stalled),
        _ => None,
    }
}

/// Why opening a stream that failed with `error` may move on to another
/// executor: it could not be reached (nothing was sent).
fn open_failure_cause(error: &StreamError) -> Option<RetryCause> {
    match error {
        StreamError::Transport(_) => Some(RetryCause::Unreachable),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_lost_streams_and_reassignments_restart() {
        assert_eq!(
            restart_cause(&StreamError::Transport("reset".into())),
            Some(RetryCause::LostAfterSend)
        );
        assert_eq!(
            restart_cause(&StreamError::PeerLost { missed: 3 }),
            Some(RetryCause::LostAfterSend)
        );
        let stall = |reassign| StreamError::Preempted {
            kind: super::super::StallKind::Producer,
            waited_ms: 1,
            reassign,
        };
        assert_eq!(restart_cause(&stall(true)), Some(RetryCause::Stalled));
        assert_eq!(restart_cause(&stall(false)), None);
        for final_error in [
            StreamError::Plugin("trap".into()),
            StreamError::Timeout { after_ms: 1 },
            StreamError::SubmitterUnresponsive { waited_ms: 1 },
            StreamError::Policy("x".into()),
            StreamError::BadEnd("x".into()),
        ] {
            assert_eq!(restart_cause(&final_error), None, "{final_error}");
        }
    }
}
