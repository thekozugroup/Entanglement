//! Submit-time validation (ATC-INT-4) and the executor's ceilings.
//!
//! Both ends refuse a stream that cannot work: the submitter before it dials
//! anyone ([`validate_submit`]), and the executor before it runs anything
//! ([`StreamCeilings::accept`]) — the executor never trusts that the
//! submitter validated.

use std::time::Duration;

use entangle_types::peer_id::PeerId;
use entangle_types::task::{ChannelSpec, IntegrityPolicy, StreamingTask};

use super::error::StreamError;
use super::frame::{WireChannel, CHUNK_FRAME_OVERHEAD};
use crate::work_unit::PolicyEnvelope;

/// The hint every integrity refusal carries: what to use instead.
pub const TRUSTED_EXECUTOR_HINT: &str = "use Integrity::TrustedExecutor: declare your own \
     NodeIds in compute.peers.trusted, then submit with --integrity trusted-executor \
     --allow <nodeid> (or Integrity::None to opt out of verification)";

/// Refuse an integrity policy a stream cannot honour (spec §7.5, ATC-INT-4).
///
/// Streams accept only [`IntegrityPolicy::TrustedExecutor`] and
/// [`IntegrityPolicy::None`]: there is one executor and chunks flow back as
/// they are produced, so there is nothing to hash-quorum or semantically
/// compare until both whole streams have ended — which loses the streaming
/// property.
pub fn check_stream_integrity(policy: &IntegrityPolicy) -> Result<(), StreamError> {
    let why = match policy {
        IntegrityPolicy::TrustedExecutor { allowlist } if allowlist.is_empty() => {
            return Err(StreamError::InvalidTask {
                field: "integrity",
                reason: "TrustedExecutor has an empty allowlist, so no executor can be \
                         trusted; name at least one peer"
                    .into(),
            })
        }
        IntegrityPolicy::TrustedExecutor { .. } | IntegrityPolicy::None => return Ok(()),
        IntegrityPolicy::Deterministic { .. } => {
            "streaming tasks cannot be hash-replicated (chunked outputs do not support \
             quorum across replicas)"
        }
        IntegrityPolicy::SemanticEquivalent { .. } => {
            "per-chunk semantic equivalence is not well-defined, and comparing whole \
             streams after both finish loses the streaming property"
        }
        IntegrityPolicy::Attested { .. } => {
            "TEE attestation is unsupported until Phase 4+, for streams as for one-shot tasks"
        }
    };
    Err(StreamError::InvalidIntegrityForStreaming {
        policy: policy.kind(),
        why: why.to_owned(),
        hint: TRUSTED_EXECUTOR_HINT.to_owned(),
    })
}

/// Refuse channel limits that cannot work.
pub fn check_channel(channel: &ChannelSpec) -> Result<(), StreamError> {
    let bad = |field, reason: &str| {
        Err(StreamError::InvalidTask {
            field,
            reason: reason.to_owned(),
        })
    };
    if channel.max_chunk_bytes == 0 {
        return bad("channel.max_chunk_bytes", "must be at least 1");
    }
    if channel.max_total_bytes == 0 {
        return bad("channel.max_total_bytes", "must be at least 1");
    }
    if channel.max_chunk_bytes > (entangle_mesh_iroh::MAX_FRAME_BYTES - CHUNK_FRAME_OVERHEAD) as u64
    {
        return bad(
            "channel.max_chunk_bytes",
            "exceeds what one transport frame can carry",
        );
    }
    if channel.credit_window == 0 {
        return bad(
            "channel.credit_window",
            "must be at least 1 (a zero window stalls on the first chunk)",
        );
    }
    if channel.heartbeat_ms == 0 {
        return bad("channel.heartbeat_ms", "must be at least 1");
    }
    if channel.credit_exhaustion_timeout_ms == 0 {
        // Spec §7.1: would stall on the first credit underflow.
        return bad(
            "channel.credit_exhaustion_timeout_ms",
            "must be greater than 0 (a zero timeout stalls on the first credit underflow)",
        );
    }
    Ok(())
}

/// Submit-time validation of a streaming task (ATC-INT-4): integrity policy,
/// channel limits, timeout and input size, then seal the policy.
///
/// Nothing is dialled and nothing runs unless this succeeds.
pub fn validate_submit(task: &StreamingTask) -> Result<PolicyEnvelope, StreamError> {
    check_stream_integrity(&task.integrity)?;
    check_channel(&task.channel)?;
    if task.timeout_ms == 0 {
        return Err(StreamError::InvalidTask {
            field: "timeout_ms",
            reason: "must be greater than 0".into(),
        });
    }
    let actual = task.input.len() as u64;
    if actual > task.max_input_bytes {
        return Err(StreamError::InputTooLarge {
            declared: task.max_input_bytes,
            actual,
        });
    }
    PolicyEnvelope::seal(&task.integrity).map_err(|e| StreamError::Policy(e.to_string()))
}

/// Refuse dispatching `policy` to `executor` unless the policy trusts it.
pub fn check_executor_allowed(
    policy: &IntegrityPolicy,
    executor: &PeerId,
) -> Result<(), StreamError> {
    match policy {
        IntegrityPolicy::TrustedExecutor { allowlist } if !allowlist.contains(executor) => {
            Err(StreamError::ExecutorNotAllowed {
                peer: executor.to_hex(),
            })
        }
        _ => Ok(()),
    }
}

/// The limits one stream runs under, after the executor's clamp.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StreamLimits {
    /// Largest chunk, either direction.
    pub max_chunk_bytes: u64,
    /// Largest cumulative byte count, per direction.
    pub max_total_bytes: u64,
    /// Output credit window (chunks the executor may have unacknowledged).
    pub credit_window: u32,
    /// Input credit window (chunks the submitter may have unacknowledged).
    pub input_window: u32,
    /// Heartbeat interval.
    pub heartbeat: Duration,
    /// How long zero credit may last before the stream is `Stalled`.
    pub credit_timeout: Duration,
    /// Wall-clock timeout for the whole stream.
    pub timeout: Duration,
}

impl StreamLimits {
    /// The limits as they travel in an `Accepted` frame.
    pub fn wire_channel(&self) -> WireChannel {
        WireChannel {
            max_chunk_bytes: self.max_chunk_bytes,
            max_total_bytes: self.max_total_bytes,
            credit_window: self.credit_window,
            heartbeat_ms: u32::try_from(self.heartbeat.as_millis()).unwrap_or(u32::MAX),
            credit_exhaustion_timeout_ms: u64::try_from(self.credit_timeout.as_millis())
                .unwrap_or(u64::MAX),
        }
    }
}

/// Hard ceilings an executor applies to every stream it serves.
///
/// Like the one-shot server's clamps, they only ever **lower** what a peer
/// asked for: a remote submitter cannot pin an executor longer, make it
/// buffer more, or send it bigger frames than these.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StreamCeilings {
    /// Wall-clock timeout ceiling for a whole stream.
    pub max_timeout_ms: u64,
    /// Ceiling on the initial input.
    pub max_input_bytes: u64,
    /// Ceiling on one chunk, either direction.
    pub max_chunk_bytes: u64,
    /// Ceiling on cumulative bytes per direction.
    pub max_total_bytes: u64,
    /// Ceiling on the output credit window.
    pub max_credit_window: u32,
    /// The input credit window this executor grants (input it buffers).
    pub input_window: u32,
    /// Heartbeat interval floor: a peer cannot make this node ping faster.
    pub min_heartbeat_ms: u32,
    /// Heartbeat interval ceiling: a peer cannot switch liveness detection
    /// off by asking for an enormous interval.
    pub max_heartbeat_ms: u32,
    /// Credit-exhaustion timeout floor: a peer cannot make this node
    /// declare a stall (and log a `StalledEvent`) more often than this, by
    /// asking for a tiny timeout and granting credit just after each stall.
    pub min_credit_exhaustion_timeout_ms: u64,
    /// Ceiling on the credit-exhaustion timeout.
    pub max_credit_exhaustion_timeout_ms: u64,
    /// Streams this executor runs at once, across all peers.
    pub max_concurrent_streams: usize,
}

/// Default ceiling on a stream's wall-clock timeout (1 hour).
pub const MAX_STREAM_TIMEOUT_MS: u64 = 60 * 60 * 1_000;

impl Default for StreamCeilings {
    fn default() -> Self {
        Self {
            max_timeout_ms: MAX_STREAM_TIMEOUT_MS,
            max_input_bytes: StreamingTask::DEFAULT_MAX_INPUT_BYTES,
            max_chunk_bytes: 4 * ChannelSpec::DEFAULT_MAX_CHUNK_BYTES,
            max_total_bytes: ChannelSpec::DEFAULT_MAX_TOTAL_BYTES,
            max_credit_window: 256,
            input_window: 16,
            min_heartbeat_ms: 1_000,
            max_heartbeat_ms: 60_000,
            min_credit_exhaustion_timeout_ms: 1_000,
            max_credit_exhaustion_timeout_ms: ChannelSpec::DEFAULT_CREDIT_EXHAUSTION_TIMEOUT_MS,
            max_concurrent_streams: 64,
        }
    }
}

impl StreamCeilings {
    /// Clamp every size and time ceiling to at most the default, and the
    /// heartbeat bounds into a sane order: configuration can tighten an
    /// executor, never loosen it past the defaults.
    ///
    /// The heartbeat and credit-exhaustion floors are the bounds a config
    /// may *lower* (down to 10 ms) — scaled-down integration tests need
    /// sub-second heartbeats and stalls.
    #[must_use]
    pub fn clamped(self) -> Self {
        let d = Self::default();
        let min_heartbeat_ms = self.min_heartbeat_ms.max(10);
        let max_credit_exhaustion_timeout_ms = self
            .max_credit_exhaustion_timeout_ms
            .clamp(10, d.max_credit_exhaustion_timeout_ms);
        Self {
            max_timeout_ms: self.max_timeout_ms.min(d.max_timeout_ms),
            max_input_bytes: self.max_input_bytes.min(d.max_input_bytes),
            max_chunk_bytes: self.max_chunk_bytes.clamp(1, d.max_chunk_bytes),
            max_total_bytes: self.max_total_bytes.clamp(1, d.max_total_bytes),
            max_credit_window: self.max_credit_window.clamp(1, d.max_credit_window),
            input_window: self.input_window.clamp(1, d.max_credit_window),
            min_heartbeat_ms,
            max_heartbeat_ms: self
                .max_heartbeat_ms
                .clamp(min_heartbeat_ms, d.max_heartbeat_ms),
            min_credit_exhaustion_timeout_ms: self
                .min_credit_exhaustion_timeout_ms
                .clamp(10, max_credit_exhaustion_timeout_ms),
            max_credit_exhaustion_timeout_ms,
            max_concurrent_streams: self.max_concurrent_streams.clamp(1, 4096),
        }
    }

    /// The limits this executor actually applies to a stream that asked for
    /// `requested` / `timeout_ms`, after refusing requests that cannot work
    /// at all (see [`check_channel`]).
    pub fn accept(
        &self,
        requested: &WireChannel,
        timeout_ms: u64,
    ) -> Result<StreamLimits, StreamError> {
        check_channel(&ChannelSpec {
            max_chunk_bytes: requested.max_chunk_bytes,
            max_total_bytes: requested.max_total_bytes,
            credit_window: requested.credit_window,
            heartbeat_ms: requested.heartbeat_ms,
            credit_exhaustion_timeout_ms: requested.credit_exhaustion_timeout_ms,
        })?;
        if timeout_ms == 0 {
            return Err(StreamError::InvalidTask {
                field: "timeout_ms",
                reason: "must be greater than 0".into(),
            });
        }
        let heartbeat_ms = requested
            .heartbeat_ms
            .clamp(self.min_heartbeat_ms, self.max_heartbeat_ms);
        Ok(StreamLimits {
            max_chunk_bytes: requested.max_chunk_bytes.min(self.max_chunk_bytes),
            max_total_bytes: requested.max_total_bytes.min(self.max_total_bytes),
            credit_window: requested.credit_window.min(self.max_credit_window),
            input_window: self.input_window,
            heartbeat: Duration::from_millis(u64::from(heartbeat_ms)),
            // `max(min).min(max)`, not `clamp`: unclamped ceilings may have
            // the floor above the ceiling, and must not panic here.
            credit_timeout: Duration::from_millis(
                requested
                    .credit_exhaustion_timeout_ms
                    .max(self.min_credit_exhaustion_timeout_ms)
                    .min(self.max_credit_exhaustion_timeout_ms),
            ),
            timeout: Duration::from_millis(timeout_ms.min(self.max_timeout_ms)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use entangle_types::task::{MetricRef, PolicyKind};

    fn task(policy: IntegrityPolicy) -> StreamingTask {
        let mut t = StreamingTask::with_defaults(
            "0123456789abcdef0123456789abcdef/s@0.1.0".parse().unwrap(),
            b"x".to_vec(),
        );
        t.integrity = policy;
        t
    }

    #[test]
    fn zero_limits_are_refused() {
        let mut t = task(IntegrityPolicy::None);
        t.channel.credit_exhaustion_timeout_ms = 0;
        assert!(matches!(
            validate_submit(&t),
            Err(StreamError::InvalidTask {
                field: "channel.credit_exhaustion_timeout_ms",
                ..
            })
        ));
        let breakers: [fn(&mut ChannelSpec); 5] = [
            |c: &mut ChannelSpec| c.credit_window = 0,
            |c: &mut ChannelSpec| c.heartbeat_ms = 0,
            |c: &mut ChannelSpec| c.max_chunk_bytes = 0,
            |c: &mut ChannelSpec| c.max_total_bytes = 0,
            |c: &mut ChannelSpec| c.max_chunk_bytes = u64::MAX,
        ];
        for f in breakers {
            let mut t = task(IntegrityPolicy::None);
            f(&mut t.channel);
            assert!(matches!(
                validate_submit(&t),
                Err(StreamError::InvalidTask { .. })
            ));
        }
        let mut t = task(IntegrityPolicy::None);
        t.timeout_ms = 0;
        assert!(validate_submit(&t).is_err());
    }

    #[test]
    fn oversized_input_is_refused_before_dispatch() {
        let mut t = task(IntegrityPolicy::None);
        t.max_input_bytes = 0;
        assert_eq!(
            validate_submit(&t).unwrap_err(),
            StreamError::InputTooLarge {
                declared: 0,
                actual: 1
            }
        );
    }

    #[test]
    fn attested_and_empty_allowlists_are_refused() {
        assert!(matches!(
            validate_submit(&task(IntegrityPolicy::Attested { tee: "sgx".into() })),
            Err(StreamError::InvalidIntegrityForStreaming {
                policy: PolicyKind::Attested,
                ..
            })
        ));
        assert!(matches!(
            validate_submit(&task(IntegrityPolicy::TrustedExecutor {
                allowlist: vec![]
            })),
            Err(StreamError::InvalidTask {
                field: "integrity",
                ..
            })
        ));
        // A semantic policy never reaches metric lookup: refused by shape.
        let semantic = IntegrityPolicy::SemanticEquivalent {
            replicas: 2,
            quorum: 1,
            metric: MetricRef {
                plugin: "0123456789abcdef0123456789abcdef/m@0.1.0".parse().unwrap(),
                publisher_key: [0; 32],
                artifact_blake3: [0; 32],
            },
            threshold: 0.5,
        };
        assert!(check_stream_integrity(&semantic).is_err());
    }

    #[test]
    fn executor_allowlist_is_enforced() {
        let a = PeerId::from_public_key_bytes(&[1; 32]);
        let b = PeerId::from_public_key_bytes(&[2; 32]);
        let policy = IntegrityPolicy::TrustedExecutor { allowlist: vec![a] };
        check_executor_allowed(&policy, &a).unwrap();
        assert!(matches!(
            check_executor_allowed(&policy, &b),
            Err(StreamError::ExecutorNotAllowed { .. })
        ));
        check_executor_allowed(&IntegrityPolicy::None, &b).unwrap();
    }

    #[test]
    fn ceilings_only_lower_requests() {
        let ceilings = StreamCeilings::default();
        let greedy = WireChannel {
            max_chunk_bytes: 8 * 1024 * 1024,
            max_total_bytes: u64::MAX,
            credit_window: u32::MAX,
            heartbeat_ms: u32::MAX,
            credit_exhaustion_timeout_ms: u64::MAX,
        };
        let l = ceilings.accept(&greedy, u64::MAX).unwrap();
        assert_eq!(l.max_chunk_bytes, ceilings.max_chunk_bytes);
        assert_eq!(l.max_total_bytes, ceilings.max_total_bytes);
        assert_eq!(l.credit_window, ceilings.max_credit_window);
        assert_eq!(l.heartbeat, Duration::from_millis(60_000));
        assert_eq!(
            l.credit_timeout,
            Duration::from_millis(ChannelSpec::DEFAULT_CREDIT_EXHAUSTION_TIMEOUT_MS)
        );
        assert_eq!(l.timeout, Duration::from_millis(MAX_STREAM_TIMEOUT_MS));

        let modest = WireChannel {
            max_chunk_bytes: 10,
            max_total_bytes: 100,
            credit_window: 2,
            heartbeat_ms: 1,
            credit_exhaustion_timeout_ms: 5,
        };
        let l = ceilings.accept(&modest, 7).unwrap();
        assert_eq!(
            (l.max_chunk_bytes, l.max_total_bytes, l.credit_window),
            (10, 100, 2)
        );
        assert_eq!(l.heartbeat, Duration::from_millis(1_000), "heartbeat floor");
        assert_eq!(
            l.credit_timeout,
            Duration::from_millis(1_000),
            "credit-exhaustion floor"
        );
        assert_eq!(l.timeout, Duration::from_millis(7));
        assert!(ceilings.accept(&modest, 0).is_err());
    }

    /// A remote submitter cannot make this node stall (and log a
    /// `StalledEvent`) every millisecond: the credit-exhaustion timeout has
    /// a floor, as the heartbeat interval does.
    #[test]
    fn a_remote_cannot_shrink_the_credit_timeout_below_the_floor() {
        let ceilings = StreamCeilings::default();
        let hasty = WireChannel {
            max_chunk_bytes: 10,
            max_total_bytes: 100,
            credit_window: 1,
            heartbeat_ms: 1_000,
            credit_exhaustion_timeout_ms: 1,
        };
        let l = ceilings.accept(&hasty, 60_000).unwrap();
        assert!(
            l.credit_timeout >= Duration::from_secs(1),
            "a 1 ms request became {:?}",
            l.credit_timeout
        );
    }

    #[test]
    fn configured_ceilings_cannot_exceed_the_defaults() {
        let loose = StreamCeilings {
            max_timeout_ms: u64::MAX,
            max_input_bytes: u64::MAX,
            max_chunk_bytes: u64::MAX,
            max_total_bytes: u64::MAX,
            max_credit_window: u32::MAX,
            input_window: u32::MAX,
            min_heartbeat_ms: 0,
            max_heartbeat_ms: u32::MAX,
            min_credit_exhaustion_timeout_ms: 0,
            max_credit_exhaustion_timeout_ms: u64::MAX,
            max_concurrent_streams: usize::MAX,
        }
        .clamped();
        let d = StreamCeilings::default();
        assert_eq!(loose.max_timeout_ms, d.max_timeout_ms);
        assert_eq!(loose.max_input_bytes, d.max_input_bytes);
        assert_eq!(loose.max_chunk_bytes, d.max_chunk_bytes);
        assert_eq!(loose.max_total_bytes, d.max_total_bytes);
        assert_eq!(loose.max_credit_window, d.max_credit_window);
        assert_eq!(loose.min_heartbeat_ms, 10);
        assert_eq!(loose.max_heartbeat_ms, d.max_heartbeat_ms);
        assert_eq!(loose.min_credit_exhaustion_timeout_ms, 10);
        assert_eq!(
            loose.max_credit_exhaustion_timeout_ms,
            d.max_credit_exhaustion_timeout_ms
        );
    }
}
