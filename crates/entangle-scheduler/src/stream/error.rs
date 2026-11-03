//! Stream errors (`ENTANGLE-E0350`–`E0399`) and the close reasons carried on
//! the wire.

use entangle_types::task::PolicyKind;
use serde::{Deserialize, Serialize};

/// Why a stream closed, as carried in `Error` / `Cancel` frames and reported
/// in a run's outcome.
///
/// A remote peer's reason is its own self-report: render it, branch on it
/// for messaging, never base a security decision on it.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Reason {
    /// The executor finished the output stream normally (`End`).
    EndOfStream,
    /// The submitter cancelled the stream.
    Cancelled,
    /// Three consecutive heartbeat pongs went missing, or the transport
    /// under the stream failed (spec §7.1, ATC-STR-2).
    PeerLost,
    /// The executor waited twice the credit-exhaustion timeout for credit
    /// and gave up (spec §7.1 `CancelReason::SubmitterUnresponsive`).
    SubmitterUnresponsive,
    /// A chunk exceeded `max_chunk_bytes`.
    ChunkSizeExceeded,
    /// The stream exceeded `max_total_bytes` (spec §7.1
    /// `Reason::TotalBytesExceeded`, ATC-INT-6).
    TotalBytesExceeded,
    /// A chunk's signature did not verify against the executor's
    /// transport-authenticated key, or its sequence number was wrong
    /// (ATC-STR-3).
    BadChunkSignature,
    /// A peer sent a data chunk it had no credit for, or granted credit
    /// beyond the window.
    CreditViolation,
    /// A peer sent a frame that is malformed or not valid in the stream's
    /// current state.
    ProtocolViolation,
    /// The stream exceeded its wall-clock timeout.
    Timeout,
    /// The submitter is not in the executor's trusted peer allowlist.
    /// **No work was done.**
    NotAuthorized,
    /// The peer speaks another stream wire version.
    UnsupportedVersion,
    /// The task's `policy_hash` is not SHA-256 of its policy bytes.
    /// **No work was done.**
    PolicyHashMismatch,
    /// The task was refused before it ran (invalid limits, integrity policy
    /// not valid for a stream, executor not in a `TrustedExecutor`
    /// allowlist, input over its limit, unparseable plugin id).
    InvalidTask,
    /// The named plugin is not loaded on the executor as a stream plugin.
    PluginNotLoaded,
    /// The plugin failed (trap, timeout, `start-stream` returned an error).
    PluginFailed,
    /// The executor has too many streams open, or this task id is already
    /// streaming for this submitter.
    Busy,
    /// An unexpected internal condition.
    Internal,
}

impl Reason {
    /// A short, stable label for logs and messages.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EndOfStream => "end-of-stream",
            Self::Cancelled => "cancelled",
            Self::PeerLost => "peer-lost",
            Self::SubmitterUnresponsive => "submitter-unresponsive",
            Self::ChunkSizeExceeded => "chunk-size-exceeded",
            Self::TotalBytesExceeded => "total-bytes-exceeded",
            Self::BadChunkSignature => "bad-chunk-signature",
            Self::CreditViolation => "credit-violation",
            Self::ProtocolViolation => "protocol-violation",
            Self::Timeout => "timeout",
            Self::NotAuthorized => "not-authorized",
            Self::UnsupportedVersion => "unsupported-version",
            Self::PolicyHashMismatch => "policy-hash-mismatch",
            Self::InvalidTask => "invalid-task",
            Self::PluginNotLoaded => "plugin-not-loaded",
            Self::PluginFailed => "plugin-failed",
            Self::Busy => "busy",
            Self::Internal => "internal",
        }
    }
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which end of a stream did something.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Side {
    /// The node that submitted the task and consumes its output.
    Submitter,
    /// The node that runs the plugin and produces the output.
    Executor,
}

impl std::fmt::Display for Side {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Submitter => "submitter",
            Self::Executor => "executor",
        })
    }
}

/// Everything that can go wrong with a streaming task.
///
/// Codes `ENTANGLE-E0350`–`E0399` belong to this enum (see the range table in
/// `entangle_types::errors`).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StreamError {
    /// `ENTANGLE-E0350` — the task's integrity policy cannot apply to a
    /// stream (ATC-INT-4): streams accept only `TrustedExecutor` or `None`.
    #[error(
        "ENTANGLE-E0350: streaming tasks cannot use integrity policy {policy}: {why}. hint: {hint}"
    )]
    InvalidIntegrityForStreaming {
        /// The refused policy variant.
        policy: PolicyKind,
        /// Why it cannot apply to a stream.
        why: String,
        /// What to use instead (always names `TrustedExecutor`).
        hint: String,
    },

    /// `ENTANGLE-E0351` — a channel limit or task field is unusable.
    #[error("ENTANGLE-E0351: invalid streaming task: {field} {reason}")]
    InvalidTask {
        /// The offending field.
        field: &'static str,
        /// What is wrong with it.
        reason: String,
    },

    /// `ENTANGLE-E0352` — a chunk did not verify against the executor's
    /// transport-authenticated key, or arrived out of sequence (ATC-STR-3).
    #[error("ENTANGLE-E0352: chunk {seq} from executor {executor} rejected: {detail}")]
    BadChunkSignature {
        /// The sequence number the chunk claimed.
        seq: u64,
        /// The executor's peer id (hex).
        executor: String,
        /// What failed: the signature, or the sequence.
        detail: String,
    },

    /// `ENTANGLE-E0353` — the stream would exceed `max_total_bytes`
    /// (ATC-INT-6).
    #[error(
        "ENTANGLE-E0353: stream exceeds max_total_bytes {limit} (would reach {attempted} bytes)"
    )]
    StreamBytesExceeded {
        /// The cap in force.
        limit: u64,
        /// The cumulative total the offending chunk would have reached (for a
        /// chunk refused from its frame header alone, a lower bound).
        attempted: u64,
    },

    /// `ENTANGLE-E0354` — one chunk exceeds `max_chunk_bytes`.
    #[error("ENTANGLE-E0354: chunk of {actual} bytes exceeds max_chunk_bytes {limit}")]
    ChunkSizeExceeded {
        /// The cap in force.
        limit: u64,
        /// The chunk's size (for a chunk refused from its frame header, a
        /// lower bound).
        actual: u64,
    },

    /// `ENTANGLE-E0355` — data sent without credit, or credit granted beyond
    /// the window.
    #[error("ENTANGLE-E0355: credit violation by the {by}: {detail}")]
    CreditViolation {
        /// Who violated the credit discipline.
        by: Side,
        /// What happened.
        detail: String,
    },

    /// `ENTANGLE-E0356` — three consecutive heartbeat pongs went missing
    /// (ATC-STR-2).
    #[error("ENTANGLE-E0356: peer lost: {missed} consecutive heartbeat pongs missed")]
    PeerLost {
        /// Consecutive missed pongs when the stream was closed.
        missed: u32,
    },

    /// `ENTANGLE-E0357` — the executor had no credit for twice the
    /// credit-exhaustion timeout and cancelled the stream (spec §7.1:
    /// `Stalled -- task_timeout * 2 --> Cancelled`).
    #[error("ENTANGLE-E0357: stream stalled: no credit for {waited_ms}ms; cancelled as submitter-unresponsive")]
    SubmitterUnresponsive {
        /// How long the executor waited with zero credit.
        waited_ms: u64,
    },

    /// `ENTANGLE-E0358` — the stream was cancelled.
    #[error("ENTANGLE-E0358: stream cancelled by the {by}")]
    Cancelled {
        /// Who cancelled.
        by: Side,
    },

    /// `ENTANGLE-E0359` — a malformed frame, or a frame not valid in the
    /// stream's current state.
    #[error("ENTANGLE-E0359: stream protocol violation by the {by}: {detail}")]
    Protocol {
        /// Who violated the protocol.
        by: Side,
        /// What happened.
        detail: String,
    },

    /// `ENTANGLE-E0360` — the peer speaks another stream wire version.
    #[error("ENTANGLE-E0360: unsupported stream wire version {got} (this node speaks {expected})")]
    UnsupportedVersion {
        /// The version the peer declared.
        got: u16,
        /// The version this node speaks.
        expected: u16,
    },

    /// `ENTANGLE-E0361` — the other end closed the stream with an `Error`
    /// frame. `message` is the peer's untrusted text.
    #[error("ENTANGLE-E0361: the {by} closed the stream ({reason}): {message}")]
    PeerAborted {
        /// Which end sent the `Error` frame.
        by: Side,
        /// Its machine-readable reason.
        reason: Reason,
        /// Its human-readable detail (untrusted; render, never parse).
        message: String,
    },

    /// `ENTANGLE-E0362` — the `End` frame does not match the chunks
    /// received (totals, transcript hash, or signature).
    #[error("ENTANGLE-E0362: end-of-stream frame rejected: {0}")]
    BadEnd(String),

    /// `ENTANGLE-E0363` — the transport under the stream failed.
    #[error("ENTANGLE-E0363: stream transport failed: {0}")]
    Transport(String),

    /// `ENTANGLE-E0364` — the stream exceeded its wall-clock timeout.
    #[error("ENTANGLE-E0364: stream exceeded its {after_ms}ms wall-clock timeout")]
    Timeout {
        /// The timeout in force.
        after_ms: u64,
    },

    /// `ENTANGLE-E0365` — the task's input exceeds `max_input_bytes`.
    #[error("ENTANGLE-E0365: stream input of {actual} bytes exceeds max_input_bytes {declared}")]
    InputTooLarge {
        /// The limit in force.
        declared: u64,
        /// The input's size.
        actual: u64,
    },

    /// `ENTANGLE-E0366` — an operation on a stream that has already closed.
    #[error("ENTANGLE-E0366: stream is closed ({0})")]
    Closed(Reason),

    /// `ENTANGLE-E0367` — the executor accepted the task under a different
    /// policy hash than the submitter sealed (INV-INT-1).
    #[error(
        "ENTANGLE-E0367: executor observed policy hash {observed}, the submitter sealed {expected}"
    )]
    PolicyHashMismatch {
        /// The hash the submitter sealed.
        expected: String,
        /// The hash the executor echoed.
        observed: String,
    },

    /// `ENTANGLE-E0368` — the chosen executor is not in the task's
    /// `TrustedExecutor` allowlist.
    #[error("ENTANGLE-E0368: executor {peer} is not in the task's TrustedExecutor allowlist")]
    ExecutorNotAllowed {
        /// The executor's peer id (hex).
        peer: String,
    },

    /// `ENTANGLE-E0369` — the plugin failed (trap, timeout, error result).
    #[error("ENTANGLE-E0369: stream plugin failed: {0}")]
    Plugin(String),

    /// `ENTANGLE-E0370` — the task's integrity policy could not be sealed or
    /// opened (no canonical encoding, or a hash mismatch).
    #[error("ENTANGLE-E0370: streaming task policy envelope rejected: {0}")]
    Policy(String),
}

impl StreamError {
    /// The wire [`Reason`] a node sends when it closes a stream because of
    /// this error.
    pub fn reason(&self) -> Reason {
        match self {
            Self::InvalidIntegrityForStreaming { .. }
            | Self::InvalidTask { .. }
            | Self::InputTooLarge { .. }
            | Self::ExecutorNotAllowed { .. } => Reason::InvalidTask,
            Self::BadChunkSignature { .. } | Self::BadEnd(_) => Reason::BadChunkSignature,
            Self::StreamBytesExceeded { .. } => Reason::TotalBytesExceeded,
            Self::ChunkSizeExceeded { .. } => Reason::ChunkSizeExceeded,
            Self::CreditViolation { .. } => Reason::CreditViolation,
            Self::PeerLost { .. } | Self::Transport(_) => Reason::PeerLost,
            Self::SubmitterUnresponsive { .. } => Reason::SubmitterUnresponsive,
            Self::Cancelled { .. } => Reason::Cancelled,
            Self::Protocol { .. } => Reason::ProtocolViolation,
            Self::UnsupportedVersion { .. } => Reason::UnsupportedVersion,
            Self::PeerAborted { reason, .. } | Self::Closed(reason) => *reason,
            Self::Timeout { .. } => Reason::Timeout,
            Self::PolicyHashMismatch { .. } | Self::Policy(_) => Reason::PolicyHashMismatch,
            Self::Plugin(_) => Reason::PluginFailed,
        }
    }

    /// The stable `ENTANGLE-E03xx` code, without the message.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidIntegrityForStreaming { .. } => "ENTANGLE-E0350",
            Self::InvalidTask { .. } => "ENTANGLE-E0351",
            Self::BadChunkSignature { .. } => "ENTANGLE-E0352",
            Self::StreamBytesExceeded { .. } => "ENTANGLE-E0353",
            Self::ChunkSizeExceeded { .. } => "ENTANGLE-E0354",
            Self::CreditViolation { .. } => "ENTANGLE-E0355",
            Self::PeerLost { .. } => "ENTANGLE-E0356",
            Self::SubmitterUnresponsive { .. } => "ENTANGLE-E0357",
            Self::Cancelled { .. } => "ENTANGLE-E0358",
            Self::Protocol { .. } => "ENTANGLE-E0359",
            Self::UnsupportedVersion { .. } => "ENTANGLE-E0360",
            Self::PeerAborted { .. } => "ENTANGLE-E0361",
            Self::BadEnd(_) => "ENTANGLE-E0362",
            Self::Transport(_) => "ENTANGLE-E0363",
            Self::Timeout { .. } => "ENTANGLE-E0364",
            Self::InputTooLarge { .. } => "ENTANGLE-E0365",
            Self::Closed(_) => "ENTANGLE-E0366",
            Self::PolicyHashMismatch { .. } => "ENTANGLE-E0367",
            Self::ExecutorNotAllowed { .. } => "ENTANGLE-E0368",
            Self::Plugin(_) => "ENTANGLE-E0369",
            Self::Policy(_) => "ENTANGLE-E0370",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Vec<StreamError> {
        vec![
            StreamError::InvalidIntegrityForStreaming {
                policy: PolicyKind::Deterministic,
                why: "w".into(),
                hint: "h".into(),
            },
            StreamError::InvalidTask {
                field: "f",
                reason: "r".into(),
            },
            StreamError::BadChunkSignature {
                seq: 1,
                executor: "e".into(),
                detail: "d".into(),
            },
            StreamError::StreamBytesExceeded {
                limit: 1,
                attempted: 2,
            },
            StreamError::ChunkSizeExceeded {
                limit: 1,
                actual: 2,
            },
            StreamError::CreditViolation {
                by: Side::Executor,
                detail: "d".into(),
            },
            StreamError::PeerLost { missed: 3 },
            StreamError::SubmitterUnresponsive { waited_ms: 1 },
            StreamError::Cancelled {
                by: Side::Submitter,
            },
            StreamError::Protocol {
                by: Side::Executor,
                detail: "d".into(),
            },
            StreamError::UnsupportedVersion {
                got: 9,
                expected: 1,
            },
            StreamError::PeerAborted {
                by: Side::Executor,
                reason: Reason::Busy,
                message: "m".into(),
            },
            StreamError::BadEnd("x".into()),
            StreamError::Transport("x".into()),
            StreamError::Timeout { after_ms: 1 },
            StreamError::InputTooLarge {
                declared: 1,
                actual: 2,
            },
            StreamError::Closed(Reason::Cancelled),
            StreamError::PolicyHashMismatch {
                expected: "a".into(),
                observed: "b".into(),
            },
            StreamError::ExecutorNotAllowed { peer: "p".into() },
            StreamError::Plugin("x".into()),
            StreamError::Policy("x".into()),
        ]
    }

    #[test]
    fn every_message_starts_with_its_code_and_codes_are_unique() {
        let mut codes: Vec<&str> = Vec::new();
        for e in all() {
            assert!(
                e.to_string().starts_with(e.code()),
                "{e} must start with {}",
                e.code()
            );
            codes.push(e.code());
        }
        let n = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), n, "duplicate stream error code");
        assert!(codes
            .iter()
            .all(|c| ("ENTANGLE-E0350"..="ENTANGLE-E0399").contains(c)));
    }

    #[test]
    fn reason_labels_are_distinct() {
        let all = [
            Reason::EndOfStream,
            Reason::Cancelled,
            Reason::PeerLost,
            Reason::SubmitterUnresponsive,
            Reason::ChunkSizeExceeded,
            Reason::TotalBytesExceeded,
            Reason::BadChunkSignature,
            Reason::CreditViolation,
            Reason::ProtocolViolation,
            Reason::Timeout,
            Reason::NotAuthorized,
            Reason::UnsupportedVersion,
            Reason::PolicyHashMismatch,
            Reason::InvalidTask,
            Reason::PluginNotLoaded,
            Reason::PluginFailed,
            Reason::Busy,
            Reason::Internal,
        ];
        let mut labels: Vec<&str> = all.iter().map(|r| r.as_str()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), all.len());
    }

    #[test]
    fn size_errors_map_to_the_spec_reasons() {
        assert_eq!(
            StreamError::StreamBytesExceeded {
                limit: 1,
                attempted: 2
            }
            .reason(),
            Reason::TotalBytesExceeded
        );
        assert_eq!(
            StreamError::ChunkSizeExceeded {
                limit: 1,
                actual: 2
            }
            .reason(),
            Reason::ChunkSizeExceeded
        );
        assert_eq!(
            StreamError::PeerLost { missed: 3 }.reason(),
            Reason::PeerLost
        );
    }
}
