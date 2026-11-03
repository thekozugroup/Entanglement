//! Run one request/response exchange with a (sandboxed) child process.
//!
//! Per invocation: spawn → write one request frame and close stdin → read one
//! response frame (refusing oversized ones from the header alone) → give the
//! child a short grace period to exit → kill its process group. The whole
//! exchange is bounded by a deadline; on expiry the process group is killed
//! with `SIGKILL`. stderr is read concurrently and forwarded line by line to
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
            let (w, r) = tokio::join!(write, read);
            let exchange = r?;
            w.map_err(SupervisorError::Io)?;
            Ok::<_, SupervisorError>(exchange)
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
                match frame::decode_response(payload) {
                    Ok(Ok(out)) => Ok(out),
                    Ok(Err(msg)) => Err(SupervisorError::PluginError(msg)),
                    Err(p) => Err(SupervisorError::Protocol(p)),
                }
            }
            Ok(Ok(Exchange::NoResponse)) => {
                let status = self.reap(&mut child, pid, deadline).await;
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
