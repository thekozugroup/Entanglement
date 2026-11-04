//! Process fault isolation (spec §2.1): a panic in core code is a clean,
//! non-zero exit the service manager restarts; a panic inside a plugin call
//! the kernel can contain becomes that call's error.
//!
//! # Pieces
//!
//! - [`install_panic_hook`] — the daemon's process-wide panic hook. Every
//!   panic writes **one** structured error line at target
//!   [`TELEMETRY_TARGET`] (`code`, `location`, `thread`, `panic` — the panic
//!   message). A panic
//!   outside a contained region, or inside a [`critical_section`], then ends
//!   the process with [`EXIT_CORE_FAULT`] (`ENTANGLE-E0787`); one inside a
//!   contained region is logged (`ENTANGLE-E0788`) and unwinds to the
//!   containing [`contain`] future, which turns it into [`Panicked`].
//! - [`contain`] — wraps one future (the kernel wraps exactly one plugin
//!   call: instantiate + guest code + the host calls it makes) so a panic
//!   raised while it is polled is caught instead of ending the daemon.
//! - [`critical_section`] — marks code whose panic must never be contained
//!   because it may leave shared security state half-updated (the
//!   capability broker's grant table). A panic inside one exits even when a
//!   [`contain`] is further up the stack.
//! - [`Supervisor`] — owns the daemon's long-lived core tasks and reports the
//!   first one that ends (by returning or by panicking) so the daemon exits
//!   with [`EXIT_CORE_FAULT`] instead of running half-working.
//! - [`inject`] / [`injected`] — test-only fault points, armed through the
//!   [`FAULT_INJECT_ENV`] environment variable. They exist only in builds
//!   with `debug_assertions`; in a release build both compile to nothing, so
//!   the variable has no effect on a shipped daemon.
//!
//! # Limits
//!
//! The containment marker is thread-local and set only while the contained
//! future is being polled, so it covers code that runs inside that poll —
//! including a Wasmtime guest's host calls, which run on a fiber of the
//! polling thread. Work the contained code hands to another thread (tokio's
//! blocking pool, e.g. WASI filesystem operations) or spawns as its own task
//! is not contained: a panic there exits.

use std::cell::Cell;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Exit status of a daemon that stopped because of a core fault: a panic
/// outside a contained plugin call, or a supervised core task that ended
/// unexpectedly. 70 is `EX_SOFTWARE` ("internal software error") from
/// `sysexits.h`; it differs from the status 1 a startup error (bad config,
/// unreadable key) exits with, so an operator can tell the two apart.
pub const EXIT_CORE_FAULT: i32 = 70;

/// The tracing target the fault lines are written to.
pub const TELEMETRY_TARGET: &str = "entangle::telemetry";

/// Stable code of the line logged before a core-fault exit.
pub const CODE_CORE_FAULT: &str = "ENTANGLE-E0787";

/// Stable code of the line logged for a contained panic.
pub const CODE_CONTAINED_PANIC: &str = "ENTANGLE-E0788";

/// Environment variable naming the armed fault points (comma-separated),
/// honoured only by builds with `debug_assertions`.
pub const FAULT_INJECT_ENV: &str = "ENTANGLE_FAULT_INJECT";

thread_local! {
    /// Number of [`Contained`] polls in progress on this thread.
    static CONTAINED: Cell<u32> = const { Cell::new(0) };
    /// Number of [`CriticalSection`]s held on this thread.
    static CRITICAL: Cell<u32> = const { Cell::new(0) };
}

/// Whether a panic raised on this thread right now would be contained.
pub fn is_contained() -> bool {
    CONTAINED.with(Cell::get) > 0 && CRITICAL.with(Cell::get) == 0
}

// ── panic hook ───────────────────────────────────────────────────────────────

/// Install the daemon's panic hook (see the module docs). Call once, early
/// in `main`, after the tracing subscriber is set up so the line is
/// formatted like every other log line (JSON when stderr is not a terminal).
///
/// Replaces any previously installed hook, including the default one that
/// prints the panic to stderr: the structured line carries the same message
/// and location.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_owned());
        let current = std::thread::current();
        let thread = current.name().unwrap_or("unnamed");
        let message = payload_message(info.payload());
        if is_contained() {
            tracing::error!(
                target: TELEMETRY_TARGET,
                code = CODE_CONTAINED_PANIC,
                contained = true,
                location = %location,
                thread = %thread,
                panic = %message,
                "ENTANGLE-E0788: panic inside a plugin call was contained; the call fails, \
                 the daemon keeps running"
            );
            return;
        }
        tracing::error!(
            target: TELEMETRY_TARGET,
            code = CODE_CORE_FAULT,
            contained = false,
            exit_code = EXIT_CORE_FAULT,
            location = %location,
            thread = %thread,
            panic = %message,
            "ENTANGLE-E0787: panic in core code; exiting so the service manager restarts \
             the daemon"
        );
        std::process::exit(EXIT_CORE_FAULT);
    }));
}

/// The text of a panic payload (`&str` or `String`; anything else is
/// described rather than shown).
pub fn payload_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

// ── containment ──────────────────────────────────────────────────────────────

/// A panic caught by [`contain`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Panicked {
    /// The panic message.
    pub message: String,
}

impl std::fmt::Display for Panicked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Run `fut` so that a panic raised while it is polled (outside any
/// [`critical_section`]) resolves it to `Err(Panicked)` instead of unwinding
/// further. The future is dropped once it has panicked.
///
/// Containment is a statement that whatever the panic interrupted is
/// discarded with the future: the kernel uses it for one plugin call, whose
/// store and instance exist only for that call.
pub fn contain<F: Future>(fut: F) -> Contained<F> {
    Contained {
        inner: Some(Box::pin(fut)),
    }
}

/// Future returned by [`contain`].
pub struct Contained<F> {
    inner: Option<Pin<Box<F>>>,
}

impl<F> std::fmt::Debug for Contained<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Contained")
            .field("done", &self.inner.is_none())
            .finish()
    }
}

/// Marks this thread as polling a contained future; unmarks on drop
/// (including during unwinding).
struct ContainMark;

impl ContainMark {
    fn enter() -> Self {
        CONTAINED.with(|c| c.set(c.get() + 1));
        Self
    }
}

impl Drop for ContainMark {
    fn drop(&mut self) {
        CONTAINED.with(|c| c.set(c.get().saturating_sub(1)));
    }
}

impl<F: Future> Future for Contained<F> {
    type Output = Result<F::Output, Panicked>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(inner) = self.inner.as_mut() else {
            // Polled again after it completed: nothing left to run.
            return Poll::Ready(Err(Panicked {
                message: "contained future polled after completion".to_owned(),
            }));
        };
        let polled = {
            let _mark = ContainMark::enter();
            std::panic::catch_unwind(AssertUnwindSafe(|| inner.as_mut().poll(cx)))
        };
        match polled {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(v)) => {
                self.inner = None;
                Poll::Ready(Ok(v))
            }
            Err(payload) => {
                self.inner = None;
                Poll::Ready(Err(Panicked {
                    message: payload_message(payload.as_ref()),
                }))
            }
        }
    }
}

/// Guard returned by [`critical_section`].
#[must_use = "the critical section ends when the guard is dropped"]
#[derive(Debug)]
pub struct CriticalSection(());

impl Drop for CriticalSection {
    fn drop(&mut self) {
        CRITICAL.with(|c| c.set(c.get().saturating_sub(1)));
    }
}

/// Enter a section whose panic always exits the process, even inside a
/// [`contain`]ed call: code that mutates shared security state (the broker's
/// grant table) and could leave it inconsistent if it unwound halfway.
///
/// The guard is per thread: never hold it across an `.await`.
pub fn critical_section() -> CriticalSection {
    CRITICAL.with(|c| c.set(c.get() + 1));
    CriticalSection(())
}

// ── supervision ──────────────────────────────────────────────────────────────

/// How a supervised core task ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskEnded {
    /// The name the task was supervised under.
    pub task: &'static str,
    /// `Some(message)` when it panicked, `None` when it returned.
    pub panic: Option<String>,
}

impl std::fmt::Display for TaskEnded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.panic {
            Some(m) => write!(f, "core task `{}` panicked: {m}", self.task),
            None => write!(f, "core task `{}` ended unexpectedly", self.task),
        }
    }
}

/// The daemon's long-lived core tasks. Any one ending while the daemon runs
/// is a fault: [`Supervisor::next_ended`] reports it and the daemon exits
/// with [`EXIT_CORE_FAULT`] (see [`TaskEnded::exit`]).
#[derive(Debug, Default)]
pub struct Supervisor {
    tasks: tokio::task::JoinSet<&'static str>,
    /// Task ids → names, for tasks that panicked (the join error carries
    /// only the id).
    names: std::collections::HashMap<tokio::task::Id, &'static str>,
}

impl Supervisor {
    /// An empty supervisor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Run `fut` as the core task `name`.
    pub fn spawn<F>(&mut self, name: &'static str, fut: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let handle = self.tasks.spawn(async move {
            fut.await;
            name
        });
        self.names.insert(handle.id(), name);
    }

    /// Supervise a task that is already running (its handle).
    pub fn watch(&mut self, name: &'static str, task: tokio::task::JoinHandle<()>) {
        self.spawn(name, async move {
            if let Err(e) = task.await {
                if let Ok(payload) = e.try_into_panic() {
                    // Re-raise inside the supervised wrapper so it is
                    // reported as this task's panic.
                    std::panic::resume_unwind(payload);
                }
            }
        });
    }

    /// Number of supervised tasks still running.
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Whether no task is supervised.
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Wait for the first supervised task to end and say how. Pending
    /// forever when nothing is supervised.
    pub async fn next_ended(&mut self) -> TaskEnded {
        match self.tasks.join_next_with_id().await {
            Some(Ok((_, task))) => TaskEnded { task, panic: None },
            Some(Err(e)) => {
                let task = self.names.get(&e.id()).copied().unwrap_or("unknown");
                let panic = match e.try_into_panic() {
                    Ok(payload) => payload_message(payload.as_ref()),
                    Err(e) => format!("cancelled: {e}"),
                };
                TaskEnded {
                    task,
                    panic: Some(panic),
                }
            }
            None => std::future::pending().await,
        }
    }

    /// Abort every supervised task (at shutdown, once they are no longer
    /// expected to run).
    pub fn abort_all(&mut self) {
        self.tasks.abort_all();
    }

    /// Abort every supervised task and wait for them to stop.
    pub async fn shutdown(mut self) {
        self.tasks.shutdown().await;
    }
}

impl TaskEnded {
    /// Log the structured fault line (`ENTANGLE-E0787`) and exit the process
    /// with [`EXIT_CORE_FAULT`].
    pub fn exit(&self) -> ! {
        tracing::error!(
            target: TELEMETRY_TARGET,
            code = CODE_CORE_FAULT,
            exit_code = EXIT_CORE_FAULT,
            task = self.task,
            panicked = self.panic.is_some(),
            reason = %self,
            "ENTANGLE-E0787: a core task ended while the daemon was running; exiting so \
             the service manager restarts the daemon"
        );
        std::process::exit(EXIT_CORE_FAULT)
    }
}

// ── fault injection (debug builds only) ──────────────────────────────────────

/// Whether the fault point `point` is armed: [`FAULT_INJECT_ENV`] lists it.
/// Always `false` in a build without `debug_assertions` (a release build).
#[inline]
pub fn injected(point: &str) -> bool {
    #[cfg(debug_assertions)]
    {
        std::env::var(FAULT_INJECT_ENV)
            .map(|v| v.split(',').any(|p| p.trim() == point))
            .unwrap_or(false)
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = point;
        false
    }
}

/// Panic at the fault point `point` when it is armed (see [`injected`]).
/// A no-op in a release build. The panic's location is the caller's.
#[inline]
#[track_caller]
pub fn inject(point: &str) {
    if injected(point) {
        panic!("fault injection: `{point}` ({FAULT_INJECT_ENV})");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn contain_turns_a_panic_into_an_error() {
        let r = contain(async {
            tokio::task::yield_now().await;
            panic!("boom in a plugin call");
        })
        .await;
        let r: Result<(), Panicked> = r;
        assert_eq!(
            r,
            Err(Panicked {
                message: "boom in a plugin call".to_owned()
            })
        );
        // The marker is cleared once the poll unwound.
        assert!(!is_contained());
    }

    #[tokio::test]
    async fn contain_passes_values_through() {
        let r = contain(async { 41 + 1 }).await;
        assert_eq!(r, Ok(42));
    }

    #[test]
    fn critical_section_is_never_contained() {
        let _mark = ContainMark::enter();
        assert!(is_contained());
        {
            let _c = critical_section();
            assert!(!is_contained(), "inside a critical section");
        }
        assert!(is_contained(), "after the critical section");
    }

    #[test]
    fn not_contained_outside_contain() {
        assert!(!is_contained());
    }

    #[tokio::test]
    async fn supervisor_reports_a_task_that_returns() {
        let mut s = Supervisor::new();
        s.spawn("steady", std::future::pending());
        s.spawn("quitter", async {});
        let ended = s.next_ended().await;
        assert_eq!(
            ended,
            TaskEnded {
                task: "quitter",
                panic: None
            }
        );
        assert_eq!(ended.to_string(), "core task `quitter` ended unexpectedly");
        s.abort_all();
    }

    #[tokio::test]
    async fn supervisor_reports_a_panicking_task_by_name() {
        let mut s = Supervisor::new();
        s.spawn("steady", std::future::pending());
        let h = tokio::spawn(async { panic!("rpc loop broke") });
        s.watch("rpc", h);
        let ended = s.next_ended().await;
        assert_eq!(ended.task, "rpc");
        assert_eq!(ended.panic.as_deref(), Some("rpc loop broke"));
        s.abort_all();
    }

    #[test]
    fn unarmed_fault_points_do_nothing() {
        // No test sets ENTANGLE_FAULT_INJECT in this process.
        assert!(!injected("entangle-core-unit-test-point"));
        inject("entangle-core-unit-test-point");
    }
}
