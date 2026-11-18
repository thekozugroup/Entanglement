//! Run one request/response exchange with a (sandboxed) child process.
//!
//! Per invocation: spawn → write one request frame and close stdin → read one
//! response frame (refusing oversized ones from the header alone) → give the
//! child a short grace period to exit → kill its process group. The whole
//! exchange is bounded by a deadline; on expiry the process group is killed
//! with `SIGKILL`, as it is when the invocation future is dropped before it
//! completes. stderr is read concurrently and forwarded line by line to
//! `tracing` (target `entangle::native`), bounded in volume, with the last
//! few lines kept for error messages.

use std::collections::VecDeque;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Child;

use crate::error::SupervisorError;
use crate::frame;

/// Limits for one invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvokeLimits {
    /// Deadline for the whole exchange, spawn to response.
    pub timeout: Duration,
    /// Largest accepted request.
    pub max_input_bytes: usize,
    /// Largest accepted response body.
    pub max_output_bytes: usize,
    /// How long a child may linger after answering before it is killed.
    pub exit_grace: Duration,
}

impl Default for InvokeLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_input_bytes: 64 * 1024 * 1024,
            max_output_bytes: 16 * 1024 * 1024,
            exit_grace: Duration::from_secs(2),
        }
    }
}

/// Longest stderr line forwarded as one log record.
const MAX_STDERR_LINE: usize = 4096;
/// stderr bytes forwarded to `tracing` per invocation; the rest is drained.
const MAX_STDERR_LOGGED: usize = 64 * 1024;
/// stderr lines retained for error messages.
const STDERR_TAIL_LINES: usize = 8;

/// Runs invocations of one plugin.
#[derive(Clone, Debug)]
pub struct Supervisor {
    label: String,
    limits: InvokeLimits,
}

enum Exchange {
    Response(Vec<u8>),
    NoResponse,
}

impl Supervisor {
    /// A supervisor whose log records and errors are tagged with `label`
    /// (normally the plugin id).
    pub fn new(label: impl Into<String>, limits: InvokeLimits) -> Self {
        Self {
            label: label.into(),
            limits,
        }
    }

    /// The limits in force.
    pub fn limits(&self) -> &InvokeLimits {
        &self.limits
    }

    /// Spawn `cmd` (normally from [`crate::sandboxed_command`]), send `input`,
    /// and return the plugin's output.
    pub async fn invoke(
        &self,
        cmd: std::process::Command,
        input: &[u8],
    ) -> Result<Vec<u8>, SupervisorError> {
        if input.len() > self.limits.max_input_bytes {
            return Err(SupervisorError::InputTooLarge {
                limit: self.limits.max_input_bytes,
                actual: input.len(),
            });
        }
        let header = frame::header(input.len()).map_err(SupervisorError::Io)?;

        let mut cmd = tokio::process::Command::from(cmd);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        cmd.process_group(0);

        let deadline = tokio::time::Instant::now() + self.limits.timeout;
        let mut child = cmd.spawn().map_err(SupervisorError::Spawn)?;
        let pid = child.id();
        // Declared after `child`, so on cancellation it drops first, while
        // the leader is still unreaped and its group id cannot be reused.
        let mut group = GroupKill { pid, armed: true };

        let tail: Arc<Mutex<VecDeque<String>>> = Arc::default();
        let stderr_task = child
            .stderr
            .take()
            .map(|err| tokio::spawn(forward_stderr(err, self.label.clone(), Arc::clone(&tail))));

        let (Some(mut stdin), Some(mut stdout)) = (child.stdin.take(), child.stdout.take()) else {
            kill_group(pid);
            return Err(SupervisorError::Io(std::io::Error::other(
                "child stdio was not captured",
            )));
        };

        let max_out = self.limits.max_output_bytes;
        let exchange = async {
            let write = async {
                // A child that exits (or stops reading) early breaks the pipe;
                // that is reported through the missing response, not here.
                let r = async {
                    stdin.write_all(&header).await?;
                    stdin.write_all(input).await?;
                    stdin.shutdown().await
                }
                .await;
                drop(stdin);
                match r {
                    Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => Err(e),
                    _ => Ok(()),
                }
            };
            let read = read_response(&mut stdout, max_out);
            tokio::pin!(write);
            tokio::pin!(read);
            let mut written = false;
            loop {
                tokio::select! {
                    w = &mut write, if !written => {
                        w.map_err(SupervisorError::Io)?;
                        written = true;
                    }
                    // The answer — or an oversized header, a protocol
                    // violation, EOF — is acted on at once, even while the
                    // request is still being written to a child that stopped
                    // reading; returning drops the write and closes stdin.
                    r = &mut read => return r,
                }
            }
        };

        let outcome = tokio::time::timeout_at(deadline, exchange).await;
        let result = match outcome {
            Err(_elapsed) => {
                kill_group(pid);
                let _ = child.kill().await;
                Err(SupervisorError::Timeout {
                    timeout_ms: u64::try_from(self.limits.timeout.as_millis()).unwrap_or(u64::MAX),
                })
            }
            Ok(Err(e)) => {
                kill_group(pid);
                let _ = child.kill().await;
                Err(e)
            }
            Ok(Ok(Exchange::Response(payload))) => {
                self.reap(&mut child, pid, deadline).await;
                // The leader is gone and its group killed, so stderr reaches
                // EOF at once: let the forwarder finish, so what the plugin
                // printed is in the log (and `entangle logs`) by the time the
                // call returns. Bounded, as on the no-response path.
                if let Some(task) = stderr_task {
                    let _ = tokio::time::timeout(Duration::from_millis(500), task).await;
                }
                match frame::decode_response(payload) {
                    Ok(Ok(out)) => Ok(out),
                    Ok(Err(msg)) => Err(SupervisorError::PluginError(msg)),
                    Err(p) => Err(SupervisorError::Protocol(p)),
                }
            }
            Ok(Ok(Exchange::NoResponse)) => {
                let status = self.reap(&mut child, pid, deadline).await;
                group.armed = false;
                if let Some(task) = stderr_task {
                    let _ = tokio::time::timeout(Duration::from_millis(500), task).await;
                }
                let stderr_tail = tail
                    .lock()
                    .map(|t| t.iter().cloned().collect::<Vec<_>>().join(" | "))
                    .unwrap_or_default();
                return Err(SupervisorError::NoResponse {
                    status,
                    stderr_tail: if stderr_tail.is_empty() {
                        "(none)".to_owned()
                    } else {
                        stderr_tail
                    },
                });
            }
        };
        // Every branch above has reaped the leader after killing its group;
        // from here its pid (and group id) may be reused.
        group.armed = false;
        result
    }

    /// Wait (bounded) for the child to exit, then kill its process group so
    /// no descendant outlives the invocation. Returns the rendered status.
    async fn reap(
        &self,
        child: &mut Child,
        pid: Option<u32>,
        deadline: tokio::time::Instant,
    ) -> String {
        let grace_end = (tokio::time::Instant::now() + self.limits.exit_grace).min(deadline);
        match tokio::time::timeout_at(grace_end, child.wait()).await {
            Ok(Ok(status)) => {
                // The leader is reaped; sweep descendants still in its group.
                // (The group id cannot be reused until every member is gone,
                // and the window is two consecutive syscalls.)
                kill_group(pid);
                status.to_string()
            }
            Ok(Err(e)) => {
                kill_group(pid);
                format!("wait failed: {e}")
            }
            Err(_) => {
                tracing::warn!(
                    target: "entangle::native",
                    plugin = %self.label,
                    "plugin did not exit after answering; killing its process group"
                );
                kill_group(pid);
                match child.wait().await {
                    Ok(s) => format!("{s} (killed after grace period)"),
                    Err(e) => format!("wait failed: {e}"),
                }
            }
        }
    }
}

async fn read_response<R: AsyncRead + Unpin>(
    r: &mut R,
    max_output: usize,
) -> Result<Exchange, SupervisorError> {
    let mut hdr = [0u8; frame::HEADER_LEN];
    let mut got = 0;
    while got < frame::HEADER_LEN {
        let n = r.read(&mut hdr[got..]).await.map_err(SupervisorError::Io)?;
        if n == 0 {
            if got == 0 {
                return Ok(Exchange::NoResponse);
            }
            return Err(SupervisorError::Protocol(
                "truncated response header".into(),
            ));
        }
        got += n;
    }
    let len = u64::from(u32::from_be_bytes(hdr));
    if len == 0 {
        return Err(SupervisorError::Protocol(
            "empty response frame (missing tag byte)".into(),
        ));
    }
    // The cap applies to the body (len - tag); checked before allocating.
    if len - 1 > max_output as u64 {
        return Err(SupervisorError::OutputTooLarge {
            limit: max_output,
            announced: len - 1,
        });
    }
    let len = usize::try_from(len)
        .map_err(|_| SupervisorError::Protocol("frame length overflows usize".into()))?;
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            SupervisorError::Protocol(format!("truncated response: expected {len} bytes"))
        } else {
            SupervisorError::Io(e)
        }
    })?;
    Ok(Exchange::Response(payload))
}

async fn forward_stderr<R: AsyncRead + Unpin>(
    mut err: R,
    label: String,
    tail: Arc<Mutex<VecDeque<String>>>,
) {
    let mut buf = [0u8; 4096];
    let mut line: Vec<u8> = Vec::new();
    let mut logged = 0usize;
    let mut truncated = false;
    let mut emit = |line: &mut Vec<u8>| {
        let text = String::from_utf8_lossy(line).trim_end().to_owned();
        line.clear();
        if text.is_empty() {
            return;
        }
        if logged < MAX_STDERR_LOGGED {
            logged += text.len();
            tracing::info!(target: "entangle::native", plugin = %label, "{text}");
        } else if !truncated {
            truncated = true;
            tracing::warn!(
                target: "entangle::native",
                plugin = %label,
                "stderr exceeded {MAX_STDERR_LOGGED} bytes; further output is discarded"
            );
        }
        if let Ok(mut t) = tail.lock() {
            if t.len() == STDERR_TAIL_LINES {
                t.pop_front();
            }
            t.push_back(text);
        }
    };
    loop {
        let n = match err.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        for &b in &buf[..n] {
            if b == b'\n' {
                emit(&mut line);
            } else if line.len() < MAX_STDERR_LINE {
                line.push(b);
            } else {
                emit(&mut line);
                line.push(b);
            }
        }
    }
    if !line.is_empty() {
        emit(&mut line);
    }
}

/// Kills the child's process group when dropped — i.e. when the invocation
/// future is cancelled (an outer timeout, task abort, shutdown) — unless
/// disarmed once the leader has been reaped. `kill_on_drop` alone only
/// signals the leader, and the deadline dies with the future, so without
/// this anything the plugin forked would outlive the invocation.
struct GroupKill {
    pid: Option<u32>,
    armed: bool,
}

impl Drop for GroupKill {
    fn drop(&mut self) {
        if self.armed {
            kill_group(self.pid);
        }
    }
}

/// `SIGKILL` the process group led by `pid` (no-op without a pid).
fn kill_group(pid: Option<u32>) {
    #[cfg(unix)]
    if let Some(pid) = pid.and_then(|p| libc::pid_t::try_from(p).ok()) {
        if pid > 0 {
            // SAFETY: plain syscall; a negative pid addresses the process
            // group the supervisor created for this child (`process_group(0)`).
            unsafe { libc::kill(-pid, libc::SIGKILL) };
        }
    }
    #[cfg(not(unix))]
    let _ = pid;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether `pid` is still a live (non-zombie) process.
    #[cfg(unix)]
    fn alive(pid: libc::pid_t) -> bool {
        // SAFETY: signal 0 only checks for existence.
        if unsafe { libc::kill(pid, 0) } != 0 {
            return false;
        }
        #[cfg(target_os = "linux")]
        if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            let state = stat[stat.rfind(')').map_or(0, |i| i + 2)..].chars().next();
            return state != Some('Z');
        }
        true
    }

    /// A child that never drains stdin (so writing a large request blocks).
    #[cfg(unix)]
    fn answers_without_reading(script: &str) -> std::process::Command {
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.arg("-c").arg(format!("{script}; exec sleep 30"));
        cmd
    }

    /// The response (or a protocol violation) is acted on as soon as it is
    /// read, even while the request is still being written: a child that
    /// answers without draining a request larger than the pipe buffer must
    /// not turn into a timeout, and an over-cap child is killed at once.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn an_early_answer_is_not_held_up_by_a_blocked_request_write() {
        let limits = InvokeLimits {
            timeout: Duration::from_secs(4),
            max_output_bytes: 1024,
            exit_grace: Duration::from_millis(100),
            ..InvokeLimits::default()
        };
        let input = vec![7u8; 1024 * 1024];
        let sup = Supervisor::new("test", limits);

        let started = std::time::Instant::now();
        // length 3 = tag 0x00 + "ok"
        let cmd = answers_without_reading(r"printf '\000\000\000\003\000ok'");
        let r = sup.invoke(cmd, &input).await;
        assert_eq!(r.ok().as_deref(), Some(&b"ok"[..]));
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );

        let started = std::time::Instant::now();
        let cmd = answers_without_reading(r"printf '\177\377\377\377'");
        let r = sup.invoke(cmd, &input).await;
        assert!(
            matches!(r, Err(SupervisorError::OutputTooLarge { limit: 1024, .. })),
            "{r:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
    }

    /// Dropping the invocation future (an outer timeout, task abort, daemon
    /// shutdown) must kill the plugin's whole process group, not only the
    /// leader: nothing the plugin forked may outlive the invocation.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn cancelling_an_invocation_kills_the_process_group() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("sleep 300 & echo $! > \"$1\"; wait")
            .arg("sh")
            .arg(&pidfile);
        let sup = Supervisor::new(
            "test",
            InvokeLimits {
                timeout: Duration::from_secs(60),
                ..InvokeLimits::default()
            },
        );
        let r = tokio::time::timeout(Duration::from_millis(700), sup.invoke(cmd, b"x")).await;
        assert!(r.is_err(), "the invocation should still be running: {r:?}");

        let pid: libc::pid_t = std::fs::read_to_string(&pidfile)
            .expect("the plugin wrote its descendant's pid")
            .trim()
            .parse()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while alive(pid) && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let survived = alive(pid);
        // SAFETY: cleanup of the test's own descendant, if it survived.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        assert!(!survived, "a descendant outlived the cancelled invocation");
    }

    #[tokio::test]
    async fn oversized_header_is_rejected_before_reading_the_body() {
        let mut data = Vec::new();
        // Length counts the tag byte: body = 1_000_001 > cap.
        data.extend_from_slice(&(1_000_002u32).to_be_bytes());
        // No body at all: the decision must come from the header alone.
        let err = match read_response(&mut &data[..], 1_000_000).await {
            Err(e) => e,
            Ok(_) => panic!("oversized frame accepted"),
        };
        assert!(
            matches!(
                err,
                SupervisorError::OutputTooLarge {
                    limit: 1_000_000,
                    announced: 1_000_001
                }
            ),
            "{err}"
        );
    }

    #[tokio::test]
    async fn exact_cap_is_accepted() {
        let mut data = Vec::new();
        frame::write_response(&mut data, Ok(&[7u8; 16])).unwrap();
        match read_response(&mut &data[..], 16).await.unwrap() {
            Exchange::Response(p) => assert_eq!(p.len(), 17),
            Exchange::NoResponse => panic!("expected a response"),
        }
    }

    #[tokio::test]
    async fn eof_before_header_is_no_response_and_partial_is_protocol() {
        assert!(matches!(
            read_response(&mut &[][..], 10).await.unwrap(),
            Exchange::NoResponse
        ));
        let err = match read_response(&mut &[0u8, 0][..], 10).await {
            Err(e) => e,
            Ok(_) => panic!("partial header accepted"),
        };
        assert!(err.to_string().contains("ENTANGLE-E0724"), "{err}");
    }
}
