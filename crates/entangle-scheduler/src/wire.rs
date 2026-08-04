//! Wire format for cross-node one-shot task dispatch.
//!
//! One request/response pair travels over a single [`ALPN_SCHEDULER`] frame
//! (see `entangle-mesh-iroh`). The encoding is [postcard] — a compact,
//! non-self-describing binary serde format that is already in this
//! workspace's dependency tree, so nothing heavy is pulled in for it.
//!
//! # Versioning
//!
//! Both envelopes carry `v` as their **first** field, so the version is the
//! first thing on the wire and the first thing decoded. [`decode_request`] and
//! [`decode_response`] read it with `postcard::take_from_bytes::<u16>` *before*
//! interpreting any remaining byte, so a future envelope shape is reported as
//! [`WireError::UnsupportedVersion`] rather than silently misparsed into
//! plausible-looking garbage.
//!
//! Postcard is not self-describing, which is exactly why this matters: without
//! the leading version a v2 message would deserialize into a v1 struct
//! whenever the field types happened to line up.
//!
//! # Untrusted input
//!
//! Every byte handled here arrives from a remote peer. The decoders therefore
//! enforce, in this order:
//!
//! 1. the frame cap ([`MAX_FRAME_BYTES`]) — before any allocation;
//! 2. the envelope version;
//! 3. structural well-formedness, with **no trailing bytes** permitted (a
//!    trailing-byte channel is a smuggling channel);
//! 4. the task's own `max_input_bytes` / `max_output_bytes` limits.
//!
//! Step 4 runs on *both* sides. A peer that answers with 4 MiB when the task
//! declared a 1 KiB ceiling is refused by the caller, not just by the
//! executor: a remote peer's response is untrusted input.
//!
//! [postcard]: https://docs.rs/postcard
//! [`ALPN_SCHEDULER`]: entangle_mesh_iroh::ALPN_SCHEDULER

use entangle_mesh_iroh::MAX_FRAME_BYTES;
use entangle_types::task::OneShotTask;
use serde::{Deserialize, Serialize};

/// Current envelope version. Bump on any change to the field layout of
/// [`RemoteTaskRequest`] or [`RemoteTaskResponse`].
pub const WIRE_VERSION: u16 = 1;

/// A request to execute one [`OneShotTask`] on the receiving node.
///
/// Deliberately **does not** carry the task's `IntegrityPolicy` or
/// `ResourceSpec`. Integrity is the *caller's* verification concern — it is
/// applied to the answers it collects — and letting a remote caller name a
/// policy would hand it an amplification primitive (`Deterministic { replicas:
/// 255 }` would be 255 executions for one frame). The executor therefore
/// always runs the task exactly once. See [`crate::remote::RemoteTaskServer`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteTaskRequest {
    /// Envelope version. Always the first field on the wire.
    pub v: u16,
    /// The task's UUID, as raw bytes (uuid's own serde form is not stable
    /// across encodings; 16 fixed bytes are).
    pub task_id: [u8; 16],
    /// Fully-qualified plugin id: `<publisher>/<name>@<version>`.
    pub plugin: String,
    /// Serialised input payload.
    pub input: Vec<u8>,
    /// Wall-clock timeout requested by the caller, in milliseconds. The
    /// executor clamps this down; it is a request, not a command.
    pub timeout_ms: u64,
    /// Caller's declared ceiling on `input`.
    pub max_input_bytes: u64,
    /// Caller's declared ceiling on the output it will accept.
    pub max_output_bytes: u64,
}

impl RemoteTaskRequest {
    /// Build a request for `task` at the current [`WIRE_VERSION`].
    pub fn for_task(task: &OneShotTask) -> Self {
        Self {
            v: WIRE_VERSION,
            task_id: *task.id.as_bytes(),
            plugin: task.plugin.to_string(),
            input: task.input.clone(),
            timeout_ms: task.timeout_ms,
            max_input_bytes: task.max_input_bytes,
            max_output_bytes: task.max_output_bytes,
        }
    }
}

/// The executor's answer to a [`RemoteTaskRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteTaskResponse {
    /// Envelope version. Always the first field on the wire.
    pub v: u16,
    /// Success payload or structured failure.
    pub outcome: RemoteOutcome,
}

impl RemoteTaskResponse {
    /// A successful response at the current [`WIRE_VERSION`].
    pub fn ok(output: Vec<u8>) -> Self {
        Self {
            v: WIRE_VERSION,
            outcome: RemoteOutcome::Ok { output },
        }
    }

    /// A failure response at the current [`WIRE_VERSION`].
    pub fn err(code: RemoteErrorCode, message: impl Into<String>) -> Self {
        Self {
            v: WIRE_VERSION,
            outcome: RemoteOutcome::Err {
                code,
                message: message.into(),
            },
        }
    }
}

/// Success payload or structured failure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteOutcome {
    /// The plugin ran and produced `output`.
    Ok {
        /// Raw output bytes from the plugin.
        output: Vec<u8>,
    },
    /// The task did not produce output. `message` is diagnostic text from the
    /// executor and is **untrusted** — render it, never parse it.
    Err {
        /// Machine-readable reason.
        code: RemoteErrorCode,
        /// Human-readable detail from the executor.
        message: String,
    },
}

/// Machine-readable reason a remote execution failed.
///
/// Kept deliberately coarse: it is a remote peer's self-report, so it drives
/// caller-side branching and messaging, never a security decision.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RemoteErrorCode {
    /// The caller is not in the executor's trusted peer allowlist, or its
    /// trust has been revoked. **No work was done.**
    NotAuthorized,
    /// The executor does not speak the caller's envelope version.
    UnsupportedVersion,
    /// The request could not be decoded, or named an unparseable plugin id.
    MalformedRequest,
    /// The named plugin is not loaded on the executor.
    PluginNotLoaded,
    /// The request's input exceeded a size limit.
    InputTooLarge,
    /// The produced output exceeded a size limit.
    OutputTooLarge,
    /// The plugin ran and failed (trap, timeout, integrity refusal, …).
    Execution,
    /// The executor hit an unexpected internal condition.
    Internal,
}

impl RemoteErrorCode {
    /// A short, stable label for logs and error messages.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAuthorized => "not-authorized",
            Self::UnsupportedVersion => "unsupported-version",
            Self::MalformedRequest => "malformed-request",
            Self::PluginNotLoaded => "plugin-not-loaded",
            Self::InputTooLarge => "input-too-large",
            Self::OutputTooLarge => "output-too-large",
            Self::Execution => "execution",
            Self::Internal => "internal",
        }
    }
}

impl std::fmt::Display for RemoteErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Failures encoding or decoding a scheduler envelope.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WireError {
    /// The peer speaks an envelope version this node does not understand.
    #[error("unsupported scheduler wire version {got} (this node speaks {expected})")]
    UnsupportedVersion {
        /// The version the peer declared.
        got: u16,
        /// The version this node speaks ([`WIRE_VERSION`]).
        expected: u16,
    },
    /// The bytes were not a well-formed envelope.
    #[error("malformed scheduler envelope: {0}")]
    Malformed(String),
    /// The frame exceeded the transport's hard cap.
    #[error("scheduler frame of {actual} bytes exceeds the {max}-byte cap")]
    FrameTooLarge {
        /// Actual encoded size.
        actual: usize,
        /// The cap in force.
        max: usize,
    },
    /// The request's input exceeded its own declared `max_input_bytes`.
    #[error("input of {actual} bytes exceeds the declared max_input_bytes {declared}")]
    InputTooLarge {
        /// The limit named in the envelope.
        declared: u64,
        /// The actual input size.
        actual: u64,
    },
    /// The response's output exceeded the caller's `max_output_bytes`.
    #[error("output of {actual} bytes exceeds the declared max_output_bytes {declared}")]
    OutputTooLarge {
        /// The limit the caller declared.
        declared: u64,
        /// The actual output size.
        actual: u64,
    },
}

/// Encode a request, refusing anything that could not be sent as one frame.
pub fn encode_request(req: &RemoteTaskRequest) -> Result<Vec<u8>, WireError> {
    encode(req)
}

/// Encode a response, refusing anything that could not be sent as one frame.
pub fn encode_response(resp: &RemoteTaskResponse) -> Result<Vec<u8>, WireError> {
    encode(resp)
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, WireError> {
    let bytes =
        postcard::to_allocvec(value).map_err(|e| WireError::Malformed(format!("encode: {e}")))?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge {
            actual: bytes.len(),
            max: MAX_FRAME_BYTES,
        });
    }
    Ok(bytes)
}

/// Decode a request from untrusted bytes.
///
/// Enforces, in order: the frame cap, the envelope version, structural
/// well-formedness with no trailing bytes, and the request's own
/// `max_input_bytes`.
pub fn decode_request(bytes: &[u8]) -> Result<RemoteTaskRequest, WireError> {
    let req: RemoteTaskRequest = decode(bytes)?;
    let actual = req.input.len() as u64;
    if actual > req.max_input_bytes {
        return Err(WireError::InputTooLarge {
            declared: req.max_input_bytes,
            actual,
        });
    }
    Ok(req)
}

/// Decode a response from untrusted bytes, enforcing `max_output_bytes`.
///
/// `max_output_bytes` is the **caller's** limit, taken from the task it
/// dispatched — not from anything the peer said. A peer that answers with more
/// than the caller agreed to accept is refused here.
pub fn decode_response(
    bytes: &[u8],
    max_output_bytes: u64,
) -> Result<RemoteTaskResponse, WireError> {
    let resp: RemoteTaskResponse = decode(bytes)?;
    if let RemoteOutcome::Ok { output } = &resp.outcome {
        let actual = output.len() as u64;
        if actual > max_output_bytes {
            return Err(WireError::OutputTooLarge {
                declared: max_output_bytes,
                actual,
            });
        }
    }
    Ok(resp)
}

/// Shared decode path: cap → version → structure → no trailing bytes.
fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, WireError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge {
            actual: bytes.len(),
            max: MAX_FRAME_BYTES,
        });
    }

    // The version is the first field of both envelopes, so it can be read
    // without committing to the rest of the layout. Do that first: an
    // unknown version must be *reported*, not misparsed.
    let (version, _) = postcard::take_from_bytes::<u16>(bytes)
        .map_err(|e| WireError::Malformed(format!("reading envelope version: {e}")))?;
    if version != WIRE_VERSION {
        return Err(WireError::UnsupportedVersion {
            got: version,
            expected: WIRE_VERSION,
        });
    }

    let (value, rest) = postcard::take_from_bytes::<T>(bytes)
        .map_err(|e| WireError::Malformed(format!("decode: {e}")))?;
    if !rest.is_empty() {
        return Err(WireError::Malformed(format!(
            "{} trailing bytes after the envelope",
            rest.len()
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use entangle_types::plugin_id::PluginId;

    fn plugin_id() -> PluginId {
        "0123456789abcdef0123456789abcdef/demo@1.0.0"
            .parse()
            .expect("fixture plugin id must parse")
    }

    fn sample_task() -> OneShotTask {
        OneShotTask::with_defaults(plugin_id(), b"world".to_vec())
    }

    #[test]
    fn request_round_trips() {
        let task = sample_task();
        let req = RemoteTaskRequest::for_task(&task);
        let decoded = decode_request(&encode_request(&req).expect("encode")).expect("decode");
        assert_eq!(decoded, req);
        assert_eq!(decoded.plugin, task.plugin.to_string());
        assert_eq!(decoded.task_id, *task.id.as_bytes());
    }

    #[test]
    fn ok_response_round_trips() {
        let resp = RemoteTaskResponse::ok(b"Hello, world!".to_vec());
        let decoded =
            decode_response(&encode_response(&resp).expect("encode"), 1024).expect("decode");
        assert_eq!(decoded, resp);
    }

    #[test]
    fn err_response_round_trips() {
        let resp = RemoteTaskResponse::err(RemoteErrorCode::NotAuthorized, "go away");
        let decoded =
            decode_response(&encode_response(&resp).expect("encode"), 1024).expect("decode");
        assert_eq!(decoded, resp);
    }

    /// The version is the first field, so a bumped envelope is *detected*
    /// rather than reinterpreted as the current shape. This is the whole
    /// point of carrying `v`.
    #[test]
    fn future_version_is_detected_not_misparsed() {
        let mut req = RemoteTaskRequest::for_task(&sample_task());
        req.v = WIRE_VERSION + 1;
        let bytes = encode_request(&req).expect("encode");

        match decode_request(&bytes) {
            Err(WireError::UnsupportedVersion { got, expected }) => {
                assert_eq!(got, WIRE_VERSION + 1);
                assert_eq!(expected, WIRE_VERSION);
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn future_response_version_is_detected() {
        let mut resp = RemoteTaskResponse::ok(b"x".to_vec());
        resp.v = 999;
        let bytes = encode_response(&resp).expect("encode");
        assert!(matches!(
            decode_response(&bytes, 1024),
            Err(WireError::UnsupportedVersion { got: 999, .. })
        ));
    }

    /// A response carrying more output than the caller agreed to accept is
    /// refused by the *caller*. The peer is untrusted; its self-declared
    /// limits are irrelevant.
    #[test]
    fn oversize_output_is_refused_by_the_caller() {
        let resp = RemoteTaskResponse::ok(vec![0u8; 4096]);
        let bytes = encode_response(&resp).expect("encode");
        match decode_response(&bytes, 16) {
            Err(WireError::OutputTooLarge { declared, actual }) => {
                assert_eq!(declared, 16);
                assert_eq!(actual, 4096);
            }
            other => panic!("expected OutputTooLarge, got {other:?}"),
        }
    }

    /// An error response is not subject to the output cap — there is no
    /// output — but its message still cannot exceed the frame cap.
    #[test]
    fn error_response_is_not_output_capped() {
        let resp = RemoteTaskResponse::err(RemoteErrorCode::Execution, "a".repeat(4096));
        let bytes = encode_response(&resp).expect("encode");
        decode_response(&bytes, 0).expect("an error response carries no output to cap");
    }

    /// A request whose input exceeds its own declared ceiling is refused at
    /// decode time, before the executor ever sees it.
    #[test]
    fn oversize_input_is_refused_at_decode() {
        let mut req = RemoteTaskRequest::for_task(&sample_task());
        req.input = vec![7u8; 512];
        req.max_input_bytes = 16;
        let bytes = encode_request(&req).expect("encode");
        match decode_request(&bytes) {
            Err(WireError::InputTooLarge { declared, actual }) => {
                assert_eq!(declared, 16);
                assert_eq!(actual, 512);
            }
            other => panic!("expected InputTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn oversize_frame_is_refused_before_decoding() {
        let bytes = vec![0u8; MAX_FRAME_BYTES + 1];
        assert!(matches!(
            decode_request(&bytes),
            Err(WireError::FrameTooLarge { max, .. }) if max == MAX_FRAME_BYTES
        ));
        assert!(matches!(
            decode_response(&bytes, u64::MAX),
            Err(WireError::FrameTooLarge { .. })
        ));
    }

    /// Trailing bytes are a smuggling channel: two peers could disagree about
    /// what a frame said. Reject rather than ignore.
    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = encode_request(&RemoteTaskRequest::for_task(&sample_task())).expect("enc");
        bytes.push(0xff);
        match decode_request(&bytes) {
            Err(WireError::Malformed(msg)) => assert!(msg.contains("trailing"), "{msg}"),
            other => panic!("expected Malformed(trailing), got {other:?}"),
        }
    }

    #[test]
    fn truncated_frame_is_malformed_not_a_panic() {
        let bytes = encode_request(&RemoteTaskRequest::for_task(&sample_task())).expect("enc");
        for cut in [0usize, 1, 2, bytes.len() / 2, bytes.len() - 1] {
            assert!(
                decode_request(&bytes[..cut]).is_err(),
                "a {cut}-byte prefix must not decode"
            );
        }
    }

    /// Random bytes must never panic the decoder.
    #[test]
    fn garbage_never_panics() {
        for seed in 0u8..=255 {
            let junk: Vec<u8> = (0..64u8)
                .map(|i| i.wrapping_mul(seed).wrapping_add(7))
                .collect();
            let _ = decode_request(&junk);
            let _ = decode_response(&junk, 1024);
        }
    }

    #[test]
    fn error_codes_have_distinct_labels() {
        let all = [
            RemoteErrorCode::NotAuthorized,
            RemoteErrorCode::UnsupportedVersion,
            RemoteErrorCode::MalformedRequest,
            RemoteErrorCode::PluginNotLoaded,
            RemoteErrorCode::InputTooLarge,
            RemoteErrorCode::OutputTooLarge,
            RemoteErrorCode::Execution,
            RemoteErrorCode::Internal,
        ];
        let mut labels: Vec<&str> = all.iter().map(|c| c.as_str()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), all.len(), "duplicate RemoteErrorCode label");
    }
}
