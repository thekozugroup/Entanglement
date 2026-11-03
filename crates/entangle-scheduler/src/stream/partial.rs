//! The result of a stream, with [`PartialResultPolicy`] applied on
//! interruption.
//!
//! Every chunk a submitter accepts has already been verified (size, credit,
//! sequence, signature — see [`super::submitter`]), so what the policy
//! decides is what an **interrupted** stream leaves behind:
//!
//! | Policy | Interrupted stream keeps |
//! |---|---|
//! | `Discard` | nothing — [`StreamResult::chunks`] is empty |
//! | `Keep` | every chunk received before the interruption, as bytes |
//! | `KeepSigned` | the same chunks **with** their executor signatures, after re-verifying the whole retained chain ([`verify_transcript`]); if that fails, nothing |
//!
//! A complete stream (a verified, signed `End`) always keeps every chunk with
//! its signature, and the `End` signature: it is attributable as a whole.

use entangle_types::task::{PartialResultPolicy, TaskId};

use super::error::StreamError;
use super::frame::Signature64;
use super::signing::{verify_transcript, SignedChunk};
use super::submitter::{EndSummary, VerifiedChunk};
use crate::work_unit::PolicyHash;

/// How a stream ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamOutcome {
    /// The executor's signed `End` arrived and verified.
    Complete(EndSummary),
    /// The stream stopped before a valid `End`.
    Interrupted(StreamError),
}

/// One chunk kept in a [`StreamResult`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedChunk {
    /// Sequence number.
    pub seq: u64,
    /// The chunk bytes.
    pub bytes: Vec<u8>,
    /// The executor's signature — present for a complete stream and under
    /// `KeepSigned`, absent under `Keep`.
    pub signature: Option<Signature64>,
}

/// What a stream produced, after the partial-result policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamResult {
    /// How it ended.
    pub outcome: StreamOutcome,
    /// The policy that was applied.
    pub policy: PartialResultPolicy,
    /// The chunks kept, in order.
    pub chunks: Vec<RetainedChunk>,
    /// Chunks received (and verified) before the end, kept or not.
    pub received_chunks: u64,
    /// Bytes received (and verified) before the end, kept or not.
    pub received_bytes: u64,
    /// The task.
    pub task_id: TaskId,
    /// The policy hash it ran under.
    pub policy_hash: PolicyHash,
    /// The executor's transport-authenticated key: what the signatures
    /// verify against.
    pub executor_key: [u8; 32],
}

impl StreamResult {
    /// `true` for a complete stream.
    pub const fn is_complete(&self) -> bool {
        matches!(self.outcome, StreamOutcome::Complete(_))
    }

    /// The kept bytes, concatenated.
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.chunks.iter().map(|c| c.bytes.len()).sum());
        for c in &self.chunks {
            out.extend_from_slice(&c.bytes);
        }
        out
    }

    /// The kept chunks as an attributable transcript, if every kept chunk
    /// carries its signature.
    pub fn signed_chunks(&self) -> Option<Vec<SignedChunk>> {
        self.chunks
            .iter()
            .map(|c| {
                c.signature.map(|signature| SignedChunk {
                    seq: c.seq,
                    bytes: c.bytes.clone(),
                    signature,
                })
            })
            .collect()
    }
}

/// Facts about the stream [`finalize`] needs besides its chunks.
#[derive(Copy, Clone, Debug)]
pub struct StreamContext {
    /// The task.
    pub task_id: TaskId,
    /// The policy hash it ran under.
    pub policy_hash: PolicyHash,
    /// The executor's transport-authenticated key.
    pub executor_key: [u8; 32],
    /// Chunks received before the end.
    pub received_chunks: u64,
    /// Bytes received before the end.
    pub received_bytes: u64,
}

/// Apply `policy` to the verified `chunks` of a stream that ended with
/// `outcome`.
pub fn finalize(
    policy: PartialResultPolicy,
    outcome: StreamOutcome,
    chunks: Vec<VerifiedChunk>,
    ctx: StreamContext,
) -> StreamResult {
    let signed = |chunks: Vec<VerifiedChunk>| {
        chunks
            .into_iter()
            .map(|c| RetainedChunk {
                seq: c.seq,
                bytes: c.bytes,
                signature: Some(c.signature),
            })
            .collect::<Vec<_>>()
    };
    let kept = match (&outcome, policy) {
        (StreamOutcome::Complete(_), _) => signed(chunks),
        (StreamOutcome::Interrupted(_), PartialResultPolicy::Discard) => Vec::new(),
        (StreamOutcome::Interrupted(_), PartialResultPolicy::Keep) => chunks
            .into_iter()
            .map(|c| RetainedChunk {
                seq: c.seq,
                bytes: c.bytes,
                signature: None,
            })
            .collect(),
        (StreamOutcome::Interrupted(_), PartialResultPolicy::KeepSigned) => {
            let transcript: Vec<SignedChunk> = chunks.iter().cloned().map(Into::into).collect();
            match verify_transcript(
                ctx.executor_key,
                *ctx.task_id.as_bytes(),
                ctx.policy_hash,
                &transcript,
            ) {
                Ok(_) => signed(chunks),
                Err(e) => {
                    tracing::warn!(
                        target: super::STREAM_TRACE_TARGET,
                        task = %ctx.task_id,
                        error = %e,
                        "partial stream result dropped: its signed transcript does not verify"
                    );
                    Vec::new()
                }
            }
        }
    };
    StreamResult {
        outcome,
        policy,
        chunks: kept,
        received_chunks: ctx.received_chunks,
        received_bytes: ctx.received_bytes,
        task_id: ctx.task_id,
        policy_hash: ctx.policy_hash,
        executor_key: ctx.executor_key,
    }
}
