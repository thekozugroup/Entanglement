//! Wire format for cross-node one-shot task dispatch.
//!
//! One request/response pair travels over a single [`ALPN_SCHEDULER`] frame
//! (see `entangle-mesh-iroh`). A request frame is either a **task** (run this
//! plugin once) or a **control** frame about a task already in flight. The encoding is [postcard] — a compact,
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
//! ## Version history
//!
//! * **v1** — task frames only; no integrity policy on the wire.
//! * **v2** — every request is a [`RemoteRequest`] (`v`, then a
//!   [`RequestFrame`]: `Task` or `Control`). A task frame carries the task's
//!   integrity policy as canonical bytes plus `policy_hash` (INV-INT-1, see
//!   [`crate::work_unit`]); a successful response echoes the hash the
//!   executor observed. v1 peers are refused with
//!   [`WireError::UnsupportedVersion`] / [`RemoteErrorCode::UnsupportedVersion`].
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
use entangle_runtime::IntegrityError;
use entangle_types::task::{OneShotTask, TaskId};
use serde::{Deserialize, Serialize};

use crate::work_unit::{PolicyEnvelope, PolicyHash, MAX_POLICY_BYTES};

/// Current envelope version. Bump on any change to the field layout of
/// [`RemoteRequest`] or [`RemoteTaskResponse`].
pub const WIRE_VERSION: u16 = 2;

/// Every frame a caller sends an executor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteRequest {
    /// Envelope version. Always the first field on the wire.
    pub v: u16,
    /// What is being asked.
    pub frame: RequestFrame,
}

impl RemoteRequest {
    /// A task frame for `task`, its policy sealed into an envelope.
    ///
    /// Fails if the task's policy has no canonical encoding (see
    /// [`PolicyEnvelope::seal`]).
    pub fn for_task(task: &OneShotTask) -> Result<Self, IntegrityError> {
        let envelope = PolicyEnvelope::seal(&task.integrity)?;
        Ok(Self::task(RemoteTaskRequest::sealed(task, &envelope)))
    }

    /// Wrap a task body at the current [`WIRE_VERSION`].
    pub fn task(body: RemoteTaskRequest) -> Self {
        Self {
            v: WIRE_VERSION,
            frame: RequestFrame::Task(body),
        }
    }

    /// Wrap a control frame at the current [`WIRE_VERSION`].
    pub fn control(frame: ControlFrame) -> Self {
        Self {
            v: WIRE_VERSION,
            frame: RequestFrame::Control(frame),
        }
    }
}

/// The two kinds of request frame.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestFrame {
    /// Execute a task once.
    Task(RemoteTaskRequest),
    /// A control message about a task this caller has in flight here.
    Control(ControlFrame),
}

/// A control message about an in-flight task.
///
/// Addressed by `task_id` **within the sending peer's own tasks**: the
/// executor keys its in-flight table by the transport-authenticated caller,
/// so one peer can never address another's task.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlFrame {
    /// The task this frame is about, as raw UUID bytes.
    pub task_id: [u8; 16],
    /// The requested action.
    pub action: ControlAction,
}

/// What a [`ControlFrame`] asks for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlAction {
    /// Replace the task's integrity policy.
    ///
    /// INV-INT-1 makes the policy immutable for a task's lifetime, so this is
    /// answered with [`RemoteOutcome::Ack`] only when the policy is
    /// *identical* (same hash — nothing changes), and with
    /// [`RemoteErrorCode::PolicyMutation`] otherwise. It exists so that a
    /// mutation attempt has one well-defined, typed refusal rather than being
    /// undefined behaviour.
    SetPolicy {
        /// Canonical bytes of the proposed policy.
        policy: Vec<u8>,
        /// `SHA-256(policy)`.
        policy_hash: PolicyHash,
    },
}

impl ControlFrame {
    /// A `SetPolicy` frame for `task_id` proposing `envelope`'s policy.
    pub fn set_policy(task_id: TaskId, envelope: &PolicyEnvelope) -> Self {
        Self {
            task_id: *task_id.as_bytes(),
            action: ControlAction::SetPolicy {
                policy: envelope.canonical().to_vec(),
                policy_hash: envelope.hash(),
            },
        }
    }
}

/// A request to execute one [`OneShotTask`] on the receiving node.
///
/// Carries the task's integrity policy — as canonical bytes plus
/// `policy_hash` — so the executor can verify the envelope (INV-INT-1) and
/// log the policy (including a `SemanticEquivalent` metric reference) for
/// audit. It does **not** make the executor *apply* the policy: integrity is
/// the caller's verification concern, applied to the answers it collects, and
/// honouring a peer-named policy would hand it an amplification primitive
/// (`Deterministic { replicas: 255 }` would be 255 executions for one frame).
/// The executor therefore always runs the task exactly once and never loads a
/// metric. See [`crate::remote::RemoteTaskServer`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteTaskRequest {
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
    /// Canonical bytes of the task's integrity policy
    /// ([`crate::work_unit::canonical_policy_bytes`]).
    pub policy: Vec<u8>,
    /// `SHA-256(policy)` as sealed by the caller.
    pub policy_hash: PolicyHash,
}

impl RemoteTaskRequest {
    /// Build the task body for `task` with an already-sealed `envelope`.
    pub fn sealed(task: &OneShotTask, envelope: &PolicyEnvelope) -> Self {
        Self {
            task_id: *task.id.as_bytes(),
            plugin: task.plugin.to_string(),
            input: task.input.clone(),
            timeout_ms: task.timeout_ms,
            max_input_bytes: task.max_input_bytes,
            max_output_bytes: task.max_output_bytes,
            policy: envelope.canonical().to_vec(),
            policy_hash: envelope.hash(),
        }
    }
}

/// The executor's answer to a [`RemoteRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteTaskResponse {
    /// Envelope version. Always the first field on the wire.
    pub v: u16,
    /// Success payload or structured failure.
    pub outcome: RemoteOutcome,
}

impl RemoteTaskResponse {
    /// A successful task response at the current [`WIRE_VERSION`], echoing
    /// the policy hash the executor observed.
    pub fn ok(output: Vec<u8>, observed_policy_hash: PolicyHash) -> Self {
        Self {
            v: WIRE_VERSION,
            outcome: RemoteOutcome::Ok {
                output,
                observed_policy_hash,
            },
        }
    }

    /// A control-frame acknowledgement at the current [`WIRE_VERSION`].
    pub fn ack(task_id: [u8; 16], observed_policy_hash: PolicyHash) -> Self {
        Self {
            v: WIRE_VERSION,
            outcome: RemoteOutcome::Ack {
                task_id,
                observed_policy_hash,
            },
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
        /// `SHA-256` of the policy bytes the executor held when it returned
        /// this result (INV-INT-1). The caller refuses the result unless it
        /// equals the hash it dispatched.
        observed_policy_hash: PolicyHash,
    },
    /// A control frame was accepted without changing anything.
    Ack {
        /// The task the frame addressed.
        task_id: [u8; 16],
        /// The (unchanged) policy hash of that in-flight task.
        observed_policy_hash: PolicyHash,
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
    /// The task frame's `policy_hash` is not `SHA-256` of its policy bytes,
    /// or the bytes are not a canonical policy. **No work was done.**
    PolicyHashMismatch,
    /// A control frame tried to change the policy of an in-flight task
    /// (INV-INT-1).
    PolicyMutation,
    /// A control frame named a task this caller has no execution of in flight
    /// on this node.
    UnknownTask,
    /// The caller already has a task with this id in flight on this node.
    /// **No work was done.**
    DuplicateTask,
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
            Self::PolicyHashMismatch => "policy-hash-mismatch",
            Self::PolicyMutation => "policy-mutation",
            Self::UnknownTask => "unknown-task",
            Self::DuplicateTask => "duplicate-task",
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
    /// A task frame's policy bytes exceed [`MAX_POLICY_BYTES`].
    #[error("policy of {actual} bytes exceeds the {max}-byte cap")]
    PolicyTooLarge {
        /// Actual policy size.
        actual: usize,
        /// The cap in force.
        max: usize,
    },
}

/// Encode a request, refusing anything that could not be sent as one frame.
pub fn encode_request(req: &RemoteRequest) -> Result<Vec<u8>, WireError> {
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
/// well-formedness with no trailing bytes, and — for a task frame — the
/// request's own `max_input_bytes` and the [`MAX_POLICY_BYTES`] cap. The
/// policy hash itself is checked by the executor
/// ([`crate::work_unit::verify_envelope`]), so it can answer with a typed
/// code.
pub fn decode_request(bytes: &[u8]) -> Result<RemoteRequest, WireError> {
    let req: RemoteRequest = decode(bytes)?;
    if let RequestFrame::Task(task) = &req.frame {
        let actual = task.input.len() as u64;
        if actual > task.max_input_bytes {
            return Err(WireError::InputTooLarge {
                declared: task.max_input_bytes,
                actual,
            });
        }
        if task.policy.len() > MAX_POLICY_BYTES {
            return Err(WireError::PolicyTooLarge {
                actual: task.policy.len(),
                max: MAX_POLICY_BYTES,
            });
        }
    }
    if let RequestFrame::Control(ControlFrame {
        action: ControlAction::SetPolicy { policy, .. },
        ..
    }) = &req.frame
    {
        if policy.len() > MAX_POLICY_BYTES {
            return Err(WireError::PolicyTooLarge {
                actual: policy.len(),
                max: MAX_POLICY_BYTES,
            });
        }
    }
    Ok(req)
}

/// Decode a response from untrusted bytes, enforcing `max_output_bytes`.
///
/// `max_output_bytes` is the **caller's** limit, taken from the task it
/// dispatched — not from anything the peer said. A peer that answers with more
/// than the caller agreed to accept is refused here.
///
/// The output size is checked **before** the no-trailing-bytes rule: an
/// oversized output with junk appended is still [`WireError::OutputTooLarge`]
/// (INV-INT-2), so appending a byte cannot turn a size violation into a plain
/// malformed frame that skips the size guard.
pub fn decode_response(
    bytes: &[u8],
    max_output_bytes: u64,
) -> Result<RemoteTaskResponse, WireError> {
    let (resp, rest) = decode_prefix::<RemoteTaskResponse>(bytes)?;
    if let RemoteOutcome::Ok { output, .. } = &resp.outcome {
        let actual = output.len() as u64;
        if actual > max_output_bytes {
            return Err(WireError::OutputTooLarge {
                declared: max_output_bytes,
                actual,
            });
        }
    }
    reject_trailing(rest)?;
    Ok(resp)
}

/// Shared decode path: cap → version → structure → no trailing bytes.
fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, WireError> {
    let (value, rest) = decode_prefix(bytes)?;
    reject_trailing(rest)?;
    Ok(value)
}

/// A frame must end where its envelope ends.
fn reject_trailing(rest: &[u8]) -> Result<(), WireError> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err(WireError::Malformed(format!(
            "{} trailing bytes after the envelope",
            rest.len()
        )))
    }
}

/// Cap → version → structure; returns the value and any bytes after it.
fn decode_prefix<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<(T, &[u8]), WireError> {
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

    postcard::take_from_bytes::<T>(bytes).map_err(|e| WireError::Malformed(format!("decode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::work_unit::policy_hash;
    use entangle_types::plugin_id::PluginId;
    use entangle_types::task::IntegrityPolicy;

    fn plugin_id() -> PluginId {
        "0123456789abcdef0123456789abcdef/demo@1.0.0"
            .parse()
            .expect("fixture plugin id must parse")
    }

    fn sample_task() -> OneShotTask {
        OneShotTask::with_defaults(plugin_id(), b"world".to_vec())
    }

    fn sample_request() -> RemoteRequest {
        RemoteRequest::for_task(&sample_task()).expect("seal")
    }

    fn task_body(req: &RemoteRequest) -> &RemoteTaskRequest {
        match &req.frame {
            RequestFrame::Task(t) => t,
            other => panic!("expected a task frame, got {other:?}"),
        }
    }

    #[test]
    fn request_round_trips() {
        let mut task = sample_task();
        task.integrity = IntegrityPolicy::Deterministic { replicas: 3 };
        let req = RemoteRequest::for_task(&task).expect("seal");
        let decoded = decode_request(&encode_request(&req).expect("encode")).expect("decode");
        assert_eq!(decoded, req);
        let body = task_body(&decoded);
        assert_eq!(body.plugin, task.plugin.to_string());
        assert_eq!(body.task_id, *task.id.as_bytes());
        // The policy travels, hashed (INV-INT-1).
        assert_eq!(body.policy_hash, policy_hash(&task.integrity));
        assert_eq!(
            crate::work_unit::verify_envelope(&body.policy, &body.policy_hash).unwrap(),
            task.integrity
        );
    }

    #[test]
    fn control_frame_round_trips() {
        let task = sample_task();
        let env = PolicyEnvelope::seal(&IntegrityPolicy::Deterministic { replicas: 2 }).unwrap();
        let req = RemoteRequest::control(ControlFrame::set_policy(task.id, &env));
        let decoded = decode_request(&encode_request(&req).expect("encode")).expect("decode");
        assert_eq!(decoded, req);
    }

    #[test]
    fn ok_response_round_trips_with_the_echoed_hash() {
        let h = policy_hash(&IntegrityPolicy::None);
        let resp = RemoteTaskResponse::ok(b"Hello, world!".to_vec(), h);
        let decoded =
            decode_response(&encode_response(&resp).expect("encode"), 1024).expect("decode");
        assert_eq!(decoded, resp);
        match decoded.outcome {
            RemoteOutcome::Ok {
                observed_policy_hash,
                ..
            } => assert_eq!(observed_policy_hash, h),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn ack_and_err_responses_round_trip() {
        let h = policy_hash(&IntegrityPolicy::None);
        for resp in [
            RemoteTaskResponse::ack([7; 16], h),
            RemoteTaskResponse::err(RemoteErrorCode::NotAuthorized, "go away"),
            RemoteTaskResponse::err(RemoteErrorCode::PolicyMutation, "immutable"),
        ] {
            let decoded =
                decode_response(&encode_response(&resp).expect("encode"), 1024).expect("decode");
            assert_eq!(decoded, resp);
        }
    }

    /// The version is the first field, so a bumped envelope is *detected*
    /// rather than reinterpreted as the current shape. This is the whole
    /// point of carrying `v`.
    #[test]
    fn future_version_is_detected_not_misparsed() {
        let mut req = sample_request();
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

    /// A v1 frame (no policy envelope) is refused as a version mismatch, not
    /// parsed into a v2 task with a garbage policy.
    #[test]
    fn a_v1_frame_is_refused_by_version() {
        #[derive(Serialize)]
        struct V1 {
            v: u16,
            task_id: [u8; 16],
            plugin: String,
            input: Vec<u8>,
            timeout_ms: u64,
            max_input_bytes: u64,
            max_output_bytes: u64,
        }
        let bytes = postcard::to_allocvec(&V1 {
            v: 1,
            task_id: [0; 16],
            plugin: plugin_id().to_string(),
            input: b"x".to_vec(),
            timeout_ms: 1,
            max_input_bytes: 16,
            max_output_bytes: 16,
        })
        .unwrap();
        assert!(matches!(
            decode_request(&bytes),
            Err(WireError::UnsupportedVersion { got: 1, .. })
        ));
    }

    #[test]
    fn future_response_version_is_detected() {
        let mut resp = RemoteTaskResponse::ok(b"x".to_vec(), policy_hash(&IntegrityPolicy::None));
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
        let resp = RemoteTaskResponse::ok(vec![0u8; 4096], policy_hash(&IntegrityPolicy::None));
        let bytes = encode_response(&resp).expect("encode");
        match decode_response(&bytes, 16) {
            Err(WireError::OutputTooLarge { declared, actual }) => {
                assert_eq!(declared, 16);
                assert_eq!(actual, 4096);
            }
            other => panic!("expected OutputTooLarge, got {other:?}"),
        }
    }

    /// An oversized output followed by a trailing byte is still an oversized
    /// output (INV-INT-2): the size is checked before the trailing-bytes
    /// rule, so appending one byte cannot turn the size violation into a
    /// plain "malformed frame" that skips the size guard's warning and
    /// penalty. A well-sized response with trailing bytes stays malformed.
    #[test]
    fn oversize_output_with_trailing_bytes_is_still_oversize() {
        let h = policy_hash(&IntegrityPolicy::None);
        let mut bytes =
            encode_response(&RemoteTaskResponse::ok(vec![b'A'; 2048], h)).expect("encode");
        bytes.push(0);
        match decode_response(&bytes, 1024) {
            Err(WireError::OutputTooLarge { declared, actual }) => {
                assert_eq!((declared, actual), (1024, 2048));
            }
            other => panic!("expected OutputTooLarge, got {other:?}"),
        }
        let mut small = encode_response(&RemoteTaskResponse::ok(vec![b'A'; 8], h)).expect("enc");
        small.push(0);
        assert!(matches!(
            decode_response(&small, 1024),
            Err(WireError::Malformed(msg)) if msg.contains("trailing")
        ));
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
        let mut req = sample_request();
        if let RequestFrame::Task(t) = &mut req.frame {
            t.input = vec![7u8; 512];
            t.max_input_bytes = 16;
        }
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
    fn oversize_policy_is_refused_at_decode() {
        let mut req = sample_request();
        if let RequestFrame::Task(t) = &mut req.frame {
            t.policy = vec![0u8; MAX_POLICY_BYTES + 1];
        }
        let bytes = encode_request(&req).expect("encode");
        assert!(matches!(
            decode_request(&bytes),
            Err(WireError::PolicyTooLarge { .. })
        ));
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
        let mut bytes = encode_request(&sample_request()).expect("enc");
        bytes.push(0xff);
        match decode_request(&bytes) {
            Err(WireError::Malformed(msg)) => assert!(msg.contains("trailing"), "{msg}"),
            other => panic!("expected Malformed(trailing), got {other:?}"),
        }
    }

    #[test]
    fn truncated_frame_is_malformed_not_a_panic() {
        let bytes = encode_request(&sample_request()).expect("enc");
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
            RemoteErrorCode::PolicyHashMismatch,
            RemoteErrorCode::PolicyMutation,
            RemoteErrorCode::UnknownTask,
            RemoteErrorCode::DuplicateTask,
        ];
        let mut labels: Vec<&str> = all.iter().map(|c| c.as_str()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), all.len(), "duplicate RemoteErrorCode label");
    }
}
