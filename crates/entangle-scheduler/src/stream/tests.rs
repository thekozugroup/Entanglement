//! State-machine edge cases for both ends of a stream, driven by explicit
//! time and wired together through the real frame codec.
//!
//! The §16 propositions themselves (ATC-INT-4/-6, ATC-STR-1/-2/-3) live in
//! `tests/stream_atc.rs`; these are the edges around them.

use std::time::{Duration, Instant};

use entangle_signing::IdentityKeyPair;
use entangle_types::peer_id::PeerId;
use entangle_types::task::{ChannelSpec, IntegrityPolicy, PartialResultPolicy, StreamingTask};

use super::frame::{
    decode_frame, encode_frame, AcceptedFrame, ChunkFrame, EndFrame, Frame, InputFrame,
    Signature64, CHUNK_FRAME_OVERHEAD, CONTROL_FRAME_MAX,
};
use super::signing::{request_digest, transcript_next, transcript_start};
use super::*;
use crate::work_unit::PolicyEnvelope;

const SEC: Duration = Duration::from_secs(1);

fn exec_key() -> IdentityKeyPair {
    IdentityKeyPair::from_seed(&[7; 32])
}

fn channel() -> ChannelSpec {
    ChannelSpec {
        max_chunk_bytes: 64,
        max_total_bytes: 1024,
        credit_window: 4,
        heartbeat_ms: 5_000,
        credit_exhaustion_timeout_ms: 5_000,
    }
}

fn task_with(channel: ChannelSpec) -> StreamingTask {
    let mut t = StreamingTask::with_defaults(
        "0123456789abcdef0123456789abcdef/stream-lines@0.1.0"
            .parse()
            .unwrap(),
        b"hello".to_vec(),
    );
    t.channel = channel;
    t.timeout_ms = 600_000;
    t
}

/// Both ends of one stream plus a simulated clock.
struct Pair {
    exec: ExecutorMachine,
    sub: SubmitterMachine,
    now: Instant,
    t0: Instant,
}

fn pair_with(task: &StreamingTask, ceilings: StreamCeilings) -> Pair {
    let t0 = Instant::now();
    let key = exec_key();
    let mut sub = SubmitterMachine::new(
        task,
        *key.public().as_bytes(),
        SubmitterOptions::default(),
        t0,
    )
    .unwrap();
    let Some(Frame::Open(open)) = sub.poll_transmit() else {
        panic!("the submitter's first frame must be Open");
    };
    let env = PolicyEnvelope::open(open.policy.clone(), open.policy_hash).unwrap();
    let limits = ceilings.accept(&open.channel, open.timeout_ms).unwrap();
    let exec = ExecutorMachine::new(
        ExecutorConfig {
            task_id: task.id,
            policy_hash: env.hash(),
            request: request_digest(&open),
            limits,
            local_peer: PeerId::from_public_key_bytes(key.public().as_bytes()),
        },
        ChunkSigner::new(key, open.task_id, env.hash(), request_digest(&open)),
        t0,
    );
    let mut p = Pair {
        exec,
        sub,
        now: t0,
        t0,
    };
    p.pump();
    assert_eq!(p.sub.state(), SubmitterState::Active);
    p
}

fn pair() -> Pair {
    pair_with(&task_with(channel()), StreamCeilings::default())
}

/// Every frame through the real codec, as the wire would carry it.
fn wire(frame: Frame, from: Side) -> Frame {
    decode_frame(&encode_frame(&frame).unwrap(), from).unwrap()
}

impl Pair {
    /// Deliver queued frames both ways until both ends are quiet.
    fn pump(&mut self) {
        self.pump_filtered(|_| false, |_| false);
    }

    fn pump_filtered(
        &mut self,
        lose_to_sub: impl Fn(&Frame) -> bool,
        lose_to_exec: impl Fn(&Frame) -> bool,
    ) {
        loop {
            let mut moved = false;
            while let Some(f) = self.exec.poll_transmit() {
                moved = true;
                if !lose_to_sub(&f) {
                    let _ = self.sub.on_frame(wire(f, Side::Executor), self.now);
                }
            }
            while let Some(f) = self.sub.poll_transmit() {
                moved = true;
                if !lose_to_exec(&f) {
                    let _ = self.exec.on_frame(wire(f, Side::Submitter), self.now);
                }
            }
            if !moved {
                return;
            }
        }
    }

    /// Run both ends' timers up to `until`, delivering frames in between.
    fn advance(&mut self, until: Instant) {
        loop {
            let next = [self.exec.poll_timeout(), self.sub.poll_timeout()]
                .into_iter()
                .flatten()
                .min();
            match next {
                Some(at) if at <= until => {
                    self.now = self.now.max(at);
                    self.exec.on_timeout(self.now);
                    self.sub.on_timeout(self.now);
                    self.pump();
                }
                _ => {
                    self.now = until;
                    return;
                }
            }
        }
    }

    fn send(&mut self, bytes: &[u8]) -> SendOutcome {
        self.exec.try_send_chunk(bytes.to_vec(), self.now).unwrap()
    }

    fn consume(&mut self) -> ChunkPoll {
        self.sub.next_chunk()
    }

    fn task_bytes(&self) -> [u8; 16] {
        *self.exec.task_id().as_bytes()
    }

    /// A chunk frame signed by `key` for this stream.
    fn chunk_signed_by(&self, key: &IdentityKeyPair, seq: u64, bytes: &[u8]) -> Frame {
        let signer = ChunkSigner::new(
            key.clone(),
            self.task_bytes(),
            self.exec.policy_hash(),
            self.sub.request_digest(),
        );
        Frame::Chunk(ChunkFrame {
            seq,
            bytes: bytes.to_vec(),
            signature: signer.sign_chunk(seq, blake3::hash(bytes).as_bytes()),
        })
    }
}

fn last_error_reason(frames: &[Frame]) -> Option<Reason> {
    frames.iter().rev().find_map(|f| match f {
        Frame::Error { reason, .. } => Some(*reason),
        _ => None,
    })
}

fn drain_sub(m: &mut SubmitterMachine) -> Vec<Frame> {
    std::iter::from_fn(|| m.poll_transmit()).collect()
}

fn drain_exec(m: &mut ExecutorMachine) -> Vec<Frame> {
    std::iter::from_fn(|| m.poll_transmit()).collect()
}

// ── credit ──────────────────────────────────────────────────────────────────

#[test]
fn credit_exactly_at_window_is_allowed_one_more_is_a_violation() {
    let mut p = pair();
    for i in 0..4u8 {
        assert!(matches!(p.send(&[i]), SendOutcome::Sent { .. }));
    }
    assert_eq!(p.exec.credit(), 0);
    p.pump();
    // Granting back up to exactly the window is fine…
    p.exec.on_frame(Frame::Credit { n: 4 }, p.now).unwrap();
    assert_eq!(p.exec.credit(), 4);
    // …one credit beyond the window is a violation.
    let err = p.exec.on_frame(Frame::Credit { n: 1 }, p.now).unwrap_err();
    assert!(
        matches!(
            err,
            StreamError::CreditViolation {
                by: Side::Submitter,
                ..
            }
        ),
        "{err}"
    );
    assert_eq!(
        p.exec.state(),
        ExecutorState::Closed(Reason::CreditViolation)
    );
    let frames = drain_exec(&mut p.exec);
    assert_eq!(last_error_reason(&frames), Some(Reason::CreditViolation));
}

#[test]
fn executor_blocks_at_zero_credit_and_resumes_when_the_submitter_consumes() {
    let mut p = pair();
    for i in 0..4u8 {
        p.send(&[i]);
    }
    assert_eq!(p.send(b"x"), SendOutcome::Blocked(b"x".to_vec()));
    p.pump();
    // Consuming half the window grants half of it back (batched credit).
    assert!(matches!(p.consume(), ChunkPoll::Chunk(c) if c.seq == 0));
    p.pump();
    assert_eq!(
        p.exec.credit(),
        0,
        "one consumed chunk is below the grant threshold"
    );
    assert!(matches!(p.consume(), ChunkPoll::Chunk(c) if c.seq == 1));
    p.pump();
    assert_eq!(p.exec.credit(), 2);
    assert_eq!(p.send(b"x"), SendOutcome::Sent { seq: 4 });
}

#[test]
fn the_submitter_refuses_a_chunk_the_executor_had_no_credit_for() {
    let mut p = pair();
    for i in 0..4u8 {
        p.send(&[i]);
    }
    p.pump();
    // A fifth, validly signed chunk without any credit granted.
    let extra = p.chunk_signed_by(&exec_key(), 4, b"x");
    let err = p.sub.on_frame(extra, p.now).unwrap_err();
    assert!(
        matches!(
            err,
            StreamError::CreditViolation {
                by: Side::Executor,
                ..
            }
        ),
        "{err}"
    );
    let frames = drain_sub(&mut p.sub);
    assert_eq!(last_error_reason(&frames), Some(Reason::CreditViolation));
}

#[test]
fn pings_flow_while_data_credit_is_zero() {
    let mut p = pair();
    for i in 0..4u8 {
        p.send(&[i]);
    }
    p.pump();
    // Nobody consumes and no credit flows, yet well past three heartbeat
    // intervals (the PeerLost threshold at the default 5 s) neither side has
    // lost the other: only answered Pings can explain that.
    p.advance(p.t0 + Duration::from_secs(20));
    assert!(matches!(
        p.exec.state(),
        ExecutorState::Active | ExecutorState::Stalled { .. }
    ));
    assert_eq!(p.sub.state(), SubmitterState::Active);
    p.exec
        .on_frame(Frame::Ping { seq: 99, ts_ms: 1 }, p.now)
        .unwrap();
    assert!(drain_exec(&mut p.exec).contains(&Frame::Pong { seq: 99, ts_ms: 1 }));
}

// ── sequence and signatures ────────────────────────────────────────────────

#[test]
fn a_duplicate_chunk_is_rejected_and_aborts_the_stream() {
    let mut p = pair();
    p.send(b"a");
    let first = p.exec.poll_transmit().unwrap();
    p.sub.on_frame(first.clone(), p.now).unwrap();
    let err = p.sub.on_frame(first, p.now).unwrap_err();
    match &err {
        StreamError::BadChunkSignature { seq: 0, detail, .. } => {
            assert!(detail.contains("replayed"), "{detail}")
        }
        other => panic!("expected BadChunkSignature, got {other}"),
    }
    assert_eq!(
        p.sub.state(),
        SubmitterState::Closed(Reason::BadChunkSignature)
    );
    let frames = drain_sub(&mut p.sub);
    assert_eq!(last_error_reason(&frames), Some(Reason::BadChunkSignature));
    // The good chunk is still delivered; then the abort.
    assert!(matches!(p.consume(), ChunkPoll::Chunk(c) if c.bytes == b"a"));
    assert!(matches!(
        p.consume(),
        ChunkPoll::Closed(StreamError::BadChunkSignature { .. })
    ));
}

#[test]
fn an_out_of_order_chunk_is_rejected() {
    let mut p = pair();
    p.send(b"a");
    p.send(b"b");
    let first = p.exec.poll_transmit().unwrap();
    let second = p.exec.poll_transmit().unwrap();
    let err = p.sub.on_frame(second, p.now).unwrap_err();
    match &err {
        StreamError::BadChunkSignature { seq: 1, detail, .. } => {
            assert!(detail.contains("out-of-order"), "{detail}")
        }
        other => panic!("expected BadChunkSignature, got {other}"),
    }
    // Later frames are ignored once closed.
    p.sub.on_frame(first, p.now).unwrap();
    assert_eq!(p.sub.chunks_received(), 0);
}

#[test]
fn a_chunk_with_altered_bytes_fails_its_signature() {
    let mut p = pair();
    p.send(b"genuine");
    let Some(Frame::Chunk(mut c)) = p.exec.poll_transmit() else {
        panic!("expected a chunk");
    };
    c.bytes = b"forged!".to_vec();
    let err = p.sub.on_frame(Frame::Chunk(c), p.now).unwrap_err();
    assert!(
        matches!(err, StreamError::BadChunkSignature { seq: 0, .. }),
        "{err}"
    );
}

// ── End ─────────────────────────────────────────────────────────────────────

fn end_frame(
    p: &Pair,
    chunks: u64,
    bytes: u64,
    transcript: [u8; 32],
    key: &IdentityKeyPair,
) -> Frame {
    let signer = ChunkSigner::new(
        key.clone(),
        p.task_bytes(),
        p.exec.policy_hash(),
        p.sub.request_digest(),
    );
    Frame::End(EndFrame {
        chunks,
        bytes,
        transcript,
        signature: signer.sign_end(chunks, bytes, &transcript),
    })
}

fn two_chunk_pair() -> (Pair, [u8; 32]) {
    let mut p = pair();
    p.send(b"ab");
    p.send(b"cde");
    p.pump();
    let t = p.sub.transcript();
    (p, t)
}

#[test]
fn end_with_wrong_totals_is_rejected() {
    for (chunks, bytes) in [(3, 5), (2, 4), (1, 2)] {
        let (mut p, t) = two_chunk_pair();
        let end = end_frame(&p, chunks, bytes, t, &exec_key());
        let err = p.sub.on_frame(end, p.now).unwrap_err();
        assert!(
            matches!(&err, StreamError::BadEnd(m) if m.contains("claims")),
            "{err}"
        );
        assert_eq!(
            p.sub.state(),
            SubmitterState::Closed(Reason::BadChunkSignature)
        );
    }
}

#[test]
fn end_with_a_wrong_transcript_or_signature_is_rejected() {
    let (mut p, _) = two_chunk_pair();
    let end = end_frame(&p, 2, 5, [0; 32], &exec_key());
    assert!(matches!(
        p.sub.on_frame(end, p.now),
        Err(StreamError::BadEnd(m)) if m.contains("transcript")
    ));

    let (mut p, t) = two_chunk_pair();
    let end = end_frame(&p, 2, 5, t, &IdentityKeyPair::from_seed(&[9; 32]));
    assert!(matches!(
        p.sub.on_frame(end, p.now),
        Err(StreamError::BadEnd(m)) if m.contains("signature")
    ));

    // The genuine End completes the stream.
    let (mut p, t) = two_chunk_pair();
    p.exec.finish(p.now).unwrap();
    p.pump();
    assert_eq!(p.sub.state(), SubmitterState::Ended);
    assert!(matches!(p.consume(), ChunkPoll::Chunk(_)));
    assert!(matches!(p.consume(), ChunkPoll::Chunk(_)));
    match p.consume() {
        ChunkPoll::Ended(end) => {
            assert_eq!((end.chunks, end.bytes, end.transcript), (2, 5, t));
        }
        other => panic!("expected Ended, got {other:?}"),
    }
}

/// A signed chunk (and End) commits to the request that produced it — the
/// plugin, its input, the requested limits — not only to the task id the
/// submitter picked: output of one request cannot be passed off as another
/// request's under a reused task id and policy.
#[test]
fn signatures_are_bound_to_the_request_not_just_the_task_id() {
    let request_a = task_with(channel());
    let mut request_b = request_a.clone();
    request_b.input = b"an innocuous prompt".to_vec();
    assert_eq!(request_a.id, request_b.id);

    let mut a = pair_with(&request_a, StreamCeilings::default());
    let mut b = pair_with(&request_b, StreamCeilings::default());
    a.send(b"output of request A");
    let chunk = a.exec.poll_transmit().unwrap();
    assert!(
        matches!(
            b.sub.on_frame(chunk, b.now),
            Err(StreamError::BadChunkSignature { seq: 0, .. })
        ),
        "a chunk produced for request A verified as request B's output"
    );

    // The same holds for the End of an empty stream.
    let mut a = pair_with(&request_a, StreamCeilings::default());
    let mut b = pair_with(&request_b, StreamCeilings::default());
    a.exec.finish(a.now).unwrap();
    let end = drain_exec(&mut a.exec)
        .into_iter()
        .find(|f| matches!(f, Frame::End(_)))
        .unwrap();
    assert!(
        matches!(b.sub.on_frame(end, b.now), Err(StreamError::BadEnd(_))),
        "request A's End verified for request B"
    );
}

#[test]
fn transcript_matches_an_independent_recomputation() {
    let (p, t) = two_chunk_pair();
    let h = transcript_start(
        &p.task_bytes(),
        &p.exec.policy_hash(),
        &p.sub.request_digest(),
    );
    let h = transcript_next(&h, 0, blake3::hash(b"ab").as_bytes());
    let h = transcript_next(&h, 1, blake3::hash(b"cde").as_bytes());
    assert_eq!(h, t);
}

// ── cancel ──────────────────────────────────────────────────────────────────

#[test]
fn cancel_mid_stream_closes_both_ends() {
    let mut p = pair();
    p.send(b"a");
    p.pump();
    p.sub.cancel();
    p.pump();
    assert_eq!(p.exec.state(), ExecutorState::Closed(Reason::Cancelled));
    assert!(matches!(
        p.exec.error(),
        Some(StreamError::Cancelled {
            by: Side::Submitter
        })
    ));
    assert_eq!(
        p.exec.try_send_chunk(b"b".to_vec(), p.now),
        Err(StreamError::Closed(Reason::Cancelled))
    );
    assert!(
        p.exec.poll_timeout().is_none(),
        "a closed stream has no timers"
    );
    // The chunk received before the cancel is still handed out.
    assert!(matches!(p.consume(), ChunkPoll::Chunk(c) if c.bytes == b"a"));
    assert!(matches!(
        p.consume(),
        ChunkPoll::Closed(StreamError::Cancelled {
            by: Side::Submitter
        })
    ));
}

#[test]
fn an_executor_error_frame_closes_the_submitter_with_its_reason() {
    let mut p = pair();
    p.exec.fail(StreamError::Plugin("trap".into()));
    p.pump();
    match p.sub.error() {
        Some(StreamError::PeerAborted {
            by: Side::Executor,
            reason,
            message,
        }) => {
            assert_eq!(*reason, Reason::PluginFailed);
            assert!(message.contains("trap"));
        }
        other => panic!("{other:?}"),
    }
}

// ── stall ───────────────────────────────────────────────────────────────────

#[test]
fn a_stall_recovers_on_credit() {
    let mut p = pair();
    for i in 0..4u8 {
        p.send(&[i]);
    }
    p.pump();
    let zero_at = p.now;
    p.advance(zero_at + 5 * SEC);
    assert!(matches!(p.exec.state(), ExecutorState::Stalled { .. }));
    // The submitter consumes; credit flows; the executor is Active again.
    p.consume();
    p.consume();
    p.pump();
    assert_eq!(p.exec.state(), ExecutorState::Active);
    let events: Vec<StreamEvent> = std::iter::from_fn(|| p.exec.poll_event()).collect();
    assert!(matches!(events[0], StreamEvent::Stalled(_)), "{events:?}");
    assert!(
        matches!(events[1], StreamEvent::Resumed { .. }),
        "{events:?}"
    );
}

#[test]
fn a_stall_that_lasts_twice_the_timeout_cancels_the_stream() {
    let mut p = pair();
    for i in 0..4u8 {
        p.send(&[i]);
    }
    p.pump();
    let zero_at = p.now;
    p.advance(zero_at + 10 * SEC - Duration::from_millis(1));
    assert!(matches!(p.exec.state(), ExecutorState::Stalled { .. }));
    p.advance(zero_at + 10 * SEC);
    assert_eq!(
        p.exec.state(),
        ExecutorState::Closed(Reason::SubmitterUnresponsive)
    );
    assert!(matches!(
        p.exec.error(),
        Some(StreamError::SubmitterUnresponsive { waited_ms: 10_000 })
    ));
    assert!(matches!(
        p.sub.error(),
        Some(StreamError::PeerAborted {
            reason: Reason::SubmitterUnresponsive,
            ..
        })
    ));
}

#[test]
fn a_finishing_plugin_ends_a_stalled_stream_normally() {
    let mut p = pair();
    for i in 0..4u8 {
        p.send(&[i]);
    }
    p.pump();
    p.advance(p.now + 6 * SEC);
    assert!(matches!(p.exec.state(), ExecutorState::Stalled { .. }));
    p.exec.finish(p.now).unwrap();
    p.pump();
    assert_eq!(p.sub.state(), SubmitterState::Ended, "End needs no credit");
}

// ── input stream ────────────────────────────────────────────────────────────

#[test]
fn input_flows_under_input_credit_and_ends_with_input_end() {
    let ceilings = StreamCeilings {
        input_window: 2,
        ..StreamCeilings::default()
    };
    let mut p = pair_with(&task_with(channel()), ceilings);
    assert_eq!(p.sub.input_credit(), 2);
    assert_eq!(
        p.sub.send_input(b"1".to_vec()).unwrap(),
        InputSend::Sent { seq: 0 }
    );
    assert_eq!(
        p.sub.send_input(b"2".to_vec()).unwrap(),
        InputSend::Sent { seq: 1 }
    );
    assert_eq!(
        p.sub.send_input(b"3".to_vec()).unwrap(),
        InputSend::Blocked(b"3".to_vec())
    );
    p.pump();
    assert_eq!(p.exec.next_input(), InputPoll::Chunk(b"1".to_vec()));
    p.pump();
    assert_eq!(
        p.sub.input_credit(),
        1,
        "consumption grants input credit back"
    );
    assert_eq!(
        p.sub.send_input(b"3".to_vec()).unwrap(),
        InputSend::Sent { seq: 2 }
    );
    assert!(p.sub.finish_input().unwrap());
    p.pump();
    assert_eq!(p.exec.next_input(), InputPoll::Chunk(b"2".to_vec()));
    assert_eq!(p.exec.next_input(), InputPoll::Chunk(b"3".to_vec()));
    assert_eq!(p.exec.next_input(), InputPoll::End);
    // Local misuse is refused without closing the stream.
    assert!(p.sub.send_input(b"4".to_vec()).is_err());
    assert_eq!(p.sub.state(), SubmitterState::Active);
}

#[test]
fn the_executor_refuses_input_without_credit_out_of_sequence_or_oversized() {
    let task = task_with(channel());
    let input = |seq, bytes: &[u8]| {
        Frame::Input(InputFrame {
            seq,
            bytes: bytes.to_vec(),
        })
    };

    let ceilings = StreamCeilings {
        input_window: 1,
        ..StreamCeilings::default()
    };
    let mut p = pair_with(&task, ceilings);
    p.exec.on_frame(input(0, b"a"), p.now).unwrap();
    let err = p.exec.on_frame(input(1, b"b"), p.now).unwrap_err();
    assert!(
        matches!(
            err,
            StreamError::CreditViolation {
                by: Side::Submitter,
                ..
            }
        ),
        "{err}"
    );

    let mut p = pair_with(&task, StreamCeilings::default());
    let err = p.exec.on_frame(input(3, b"a"), p.now).unwrap_err();
    assert!(
        matches!(
            err,
            StreamError::Protocol {
                by: Side::Submitter,
                ..
            }
        ),
        "{err}"
    );

    let mut p = pair_with(&task, StreamCeilings::default());
    let err = p.exec.on_frame(input(0, &[0; 65]), p.now).unwrap_err();
    assert_eq!(
        err,
        StreamError::ChunkSizeExceeded {
            limit: 64,
            actual: 65
        }
    );

    let mut p = pair_with(&task, StreamCeilings::default());
    let err = p
        .exec
        .on_frame(
            Frame::InputEnd {
                chunks: 2,
                bytes: 0,
            },
            p.now,
        )
        .unwrap_err();
    assert!(
        matches!(err, StreamError::Protocol { .. }),
        "InputEnd totals must match"
    );
}

// ── sizes ───────────────────────────────────────────────────────────────────

#[test]
fn an_oversized_plugin_chunk_is_never_sent_and_closes_the_stream() {
    let mut p = pair();
    let err = p.exec.try_send_chunk(vec![0; 65], p.now).unwrap_err();
    assert_eq!(
        err,
        StreamError::ChunkSizeExceeded {
            limit: 64,
            actual: 65
        }
    );
    p.pump();
    assert!(matches!(
        p.sub.error(),
        Some(StreamError::PeerAborted {
            reason: Reason::ChunkSizeExceeded,
            ..
        })
    ));
    assert_eq!(p.sub.chunks_received(), 0, "the oversized chunk never left");
}

#[test]
fn frame_caps_tighten_with_the_remaining_budget() {
    let mut p = pair_with(
        &task_with(ChannelSpec {
            max_chunk_bytes: 4096,
            max_total_bytes: 5000,
            ..channel()
        }),
        StreamCeilings::default(),
    );
    assert_eq!(p.sub.frame_cap(), 4096 + CHUNK_FRAME_OVERHEAD);
    p.send(&[1; 4096]);
    p.pump();
    assert_eq!(
        p.sub.frame_cap(),
        CONTROL_FRAME_MAX.max(904 + CHUNK_FRAME_OVERHEAD)
    );
    p.send(&[1; 904]);
    p.pump();
    // Nothing left in the budget: only control frames fit.
    assert_eq!(p.sub.frame_cap(), CONTROL_FRAME_MAX);
}

#[test]
fn an_oversized_frame_header_maps_to_the_cap_it_broke() {
    let mut p = pair();
    let over_chunk = (64 + CHUNK_FRAME_OVERHEAD + 1) as u64;
    assert!(matches!(
        p.sub.on_oversized_frame(over_chunk),
        StreamError::ChunkSizeExceeded { limit: 64, .. }
    ));
    let mut p = pair_with(
        &task_with(ChannelSpec {
            max_chunk_bytes: 64,
            max_total_bytes: 100,
            ..channel()
        }),
        StreamCeilings::default(),
    );
    p.send(&[0; 60]);
    p.pump();
    let in_chunk_cap = (50 + CHUNK_FRAME_OVERHEAD) as u64;
    assert!(matches!(
        p.sub.on_oversized_frame(in_chunk_cap),
        StreamError::StreamBytesExceeded {
            limit: 100,
            attempted: 110
        }
    ));
}

/// A chunk costs the submitter bookkeeping whatever its size, so the number
/// of chunks is capped too: `max_total_bytes` alone would let an executor
/// stream millions of empty (or one-byte) chunks into a consumer that keeps
/// them. An honest executor stops at the allowance; one that does not is
/// torn down by the submitter.
#[test]
fn the_chunk_count_is_capped_on_both_ends() {
    // 1 KiB of total budget allows the minimum allowance of chunks.
    let allowance = 1024;

    // Executor: empty chunks pass every byte check, but not the count.
    let mut p = pair();
    for _ in 0..allowance {
        assert!(matches!(p.send(b""), SendOutcome::Sent { .. }));
        p.pump();
        assert!(matches!(p.consume(), ChunkPoll::Chunk(_)));
        p.pump();
    }
    let err = p.exec.try_send_chunk(Vec::new(), p.now).unwrap_err();
    assert_eq!(err.reason(), Reason::TotalBytesExceeded, "{err}");
    p.pump();
    assert!(matches!(
        p.sub.error(),
        Some(StreamError::PeerAborted {
            reason: Reason::TotalBytesExceeded,
            ..
        })
    ));

    // Submitter: an executor that keeps going is refused at the allowance.
    let mut p = pair();
    let key = exec_key();
    for seq in 0..allowance {
        let chunk = p.chunk_signed_by(&key, seq, b"");
        p.sub.on_frame(chunk, p.now).unwrap();
        assert!(matches!(p.consume(), ChunkPoll::Chunk(_)));
    }
    let extra = p.chunk_signed_by(&key, allowance, b"");
    let err = p.sub.on_frame(extra, p.now).unwrap_err();
    assert_eq!(err.reason(), Reason::TotalBytesExceeded, "{err}");
    assert_eq!(p.sub.chunks_received(), allowance);
    assert_eq!(
        last_error_reason(&drain_sub(&mut p.sub)),
        Some(Reason::TotalBytesExceeded)
    );
}

// ── accepted / limits ───────────────────────────────────────────────────────

fn fresh_submitter(task: &StreamingTask) -> (SubmitterMachine, super::frame::OpenFrame) {
    let mut sub = SubmitterMachine::new(
        task,
        *exec_key().public().as_bytes(),
        SubmitterOptions::default(),
        Instant::now(),
    )
    .unwrap();
    let Some(Frame::Open(open)) = sub.poll_transmit() else {
        panic!("expected Open");
    };
    (sub, open)
}

#[test]
fn accepted_under_another_policy_hash_is_refused() {
    let task = task_with(channel());
    let (mut sub, _) = fresh_submitter(&task);
    let other = PolicyEnvelope::seal(&IntegrityPolicy::TrustedExecutor {
        allowlist: vec![PeerId::from_public_key_bytes(&[1; 32])],
    })
    .unwrap();
    let err = sub
        .on_frame(
            Frame::Accepted(AcceptedFrame {
                observed_policy_hash: other.hash(),
                channel: (&task.channel).into(),
                input_window: 4,
                timeout_ms: 1,
            }),
            Instant::now(),
        )
        .unwrap_err();
    assert!(
        matches!(err, StreamError::PolicyHashMismatch { .. }),
        "{err}"
    );
}

#[test]
fn an_executor_that_raises_a_limit_gains_nothing() {
    let task = task_with(channel());
    let (mut sub, open) = fresh_submitter(&task);
    let mut greedy: super::frame::WireChannel = (&task.channel).into();
    greedy.max_chunk_bytes = 1 << 20;
    greedy.credit_window = 1000;
    sub.on_frame(
        Frame::Accepted(AcceptedFrame {
            observed_policy_hash: open.policy_hash,
            channel: greedy,
            input_window: 4,
            timeout_ms: 1,
        }),
        Instant::now(),
    )
    .unwrap();
    // The submitter's own 64-byte cap still applies.
    assert_eq!(sub.frame_cap(), CONTROL_FRAME_MAX);
    let signer = ChunkSigner::new(
        exec_key(),
        open.task_id,
        open.policy_hash,
        request_digest(&open),
    );
    let big = vec![0u8; 65];
    let err = sub
        .on_frame(
            Frame::Chunk(ChunkFrame {
                seq: 0,
                signature: signer.sign_chunk(0, blake3::hash(&big).as_bytes()),
                bytes: big,
            }),
            Instant::now(),
        )
        .unwrap_err();
    assert_eq!(
        err,
        StreamError::ChunkSizeExceeded {
            limit: 64,
            actual: 65
        }
    );
}

#[test]
fn unexpected_frames_are_protocol_violations() {
    let mut p = pair();
    let err = p
        .sub
        .on_frame(
            Frame::Input(InputFrame {
                seq: 0,
                bytes: vec![],
            }),
            p.now,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        StreamError::Protocol {
            by: Side::Executor,
            ..
        }
    ));
    let mut p = pair();
    let err = p
        .exec
        .on_frame(
            Frame::Chunk(ChunkFrame {
                seq: 0,
                bytes: vec![],
                signature: Signature64::from_bytes([0; 64]),
            }),
            p.now,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        StreamError::Protocol {
            by: Side::Submitter,
            ..
        }
    ));
}

#[test]
fn the_wall_clock_deadline_closes_the_executor() {
    let mut task = task_with(channel());
    task.timeout_ms = 20_000;
    let mut p = pair_with(&task, StreamCeilings::default());
    p.advance(p.t0 + Duration::from_secs(20));
    assert!(matches!(
        p.exec.error(),
        Some(StreamError::Timeout { after_ms: 20_000 })
    ));
    assert!(matches!(
        p.sub.error(),
        Some(StreamError::PeerAborted {
            reason: Reason::Timeout,
            ..
        })
    ));
}

#[test]
fn an_executor_that_never_accepts_times_out() {
    let task = task_with(channel());
    let t0 = Instant::now();
    let mut sub = SubmitterMachine::new(
        &task,
        *exec_key().public().as_bytes(),
        SubmitterOptions::default(),
        t0,
    )
    .unwrap();
    assert_eq!(
        sub.poll_timeout(),
        Some(t0 + submitter::DEFAULT_OPEN_TIMEOUT)
    );
    sub.on_timeout(t0 + submitter::DEFAULT_OPEN_TIMEOUT);
    assert!(matches!(sub.error(), Some(StreamError::Timeout { .. })));
}

// ── partial results ─────────────────────────────────────────────────────────

fn interrupted_chunks() -> (Vec<VerifiedChunk>, StreamContext) {
    let mut p = pair();
    p.send(b"one ");
    p.send(b"two ");
    p.pump();
    let mut chunks = Vec::new();
    for _ in 0..2 {
        match p.consume() {
            ChunkPoll::Chunk(c) => chunks.push(c),
            other => panic!("{other:?}"),
        }
    }
    let ctx = StreamContext {
        task_id: p.exec.task_id(),
        policy_hash: p.exec.policy_hash(),
        request_digest: p.sub.request_digest(),
        executor_key: *exec_key().public().as_bytes(),
        received_chunks: 2,
        received_bytes: 8,
    };
    (chunks, ctx)
}

fn lost() -> StreamOutcome {
    StreamOutcome::Interrupted(StreamError::PeerLost { missed: 3 })
}

#[test]
fn discard_drops_an_interrupted_stream() {
    let (chunks, ctx) = interrupted_chunks();
    let r = finalize(PartialResultPolicy::Discard, lost(), chunks, ctx);
    assert!(r.chunks.is_empty());
    assert!(!r.is_complete());
    assert_eq!(
        (r.received_chunks, r.received_bytes),
        (2, 8),
        "still accounted"
    );
}

#[test]
fn keep_returns_the_partial_bytes_without_signatures() {
    let (chunks, ctx) = interrupted_chunks();
    let r = finalize(PartialResultPolicy::Keep, lost(), chunks, ctx);
    assert_eq!(r.bytes(), b"one two ");
    assert!(r.chunks.iter().all(|c| c.signature.is_none()));
    assert!(r.signed_chunks().is_none());
}

#[test]
fn keep_signed_returns_an_attributable_partial_transcript() {
    let (chunks, ctx) = interrupted_chunks();
    let r = finalize(PartialResultPolicy::KeepSigned, lost(), chunks, ctx);
    assert_eq!(r.bytes(), b"one two ");
    let signed = r.signed_chunks().expect("every kept chunk is signed");
    verify_transcript(
        ctx.executor_key,
        *ctx.task_id.as_bytes(),
        ctx.policy_hash,
        ctx.request_digest,
        &signed,
    )
    .expect("a third party can re-verify the partial result");
    // A transcript that does not verify against the executor's key is not kept.
    let mut wrong = ctx;
    wrong.executor_key = *IdentityKeyPair::from_seed(&[1; 32]).public().as_bytes();
    let (chunks, _) = interrupted_chunks();
    let r = finalize(PartialResultPolicy::KeepSigned, lost(), chunks, wrong);
    assert!(r.chunks.is_empty());
}

#[test]
fn a_complete_stream_keeps_everything_signed_under_any_policy() {
    for policy in [
        PartialResultPolicy::Discard,
        PartialResultPolicy::Keep,
        PartialResultPolicy::KeepSigned,
    ] {
        let (chunks, ctx) = interrupted_chunks();
        let end = EndSummary {
            chunks: 2,
            bytes: 8,
            transcript: [0; 32],
            signature: Signature64::from_bytes([0; 64]),
        };
        let r = finalize(policy, StreamOutcome::Complete(end), chunks, ctx);
        assert!(r.is_complete());
        assert_eq!(r.bytes(), b"one two ");
        assert!(r.signed_chunks().is_some());
    }
}

#[test]
fn grant_threshold_is_half_the_window_but_at_least_one() {
    assert_eq!(grant_threshold(0), 1);
    assert_eq!(grant_threshold(1), 1);
    assert_eq!(grant_threshold(2), 1);
    assert_eq!(grant_threshold(16), 8);
    assert_eq!(grant_threshold(33), 16);
}

// ── async drivers ───────────────────────────────────────────────────────────

/// A guest that computes for many heartbeat intervals before its first
/// `yield-chunk` (an LLM processing a long prompt) must not get its stream
/// declared lost: the plugin runs on its own task, so the executor's loop
/// keeps answering pings while the guest holds its thread.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn heartbeats_are_answered_while_the_plugin_computes() {
    use entangle_host::{stream_port, OUTPUT_HANDLE};
    use entangle_mesh_iroh::{duplex_pair, DEFAULT_DUPLEX_BUFFER, MAX_FRAME_BYTES};

    let exec = exec_key();
    let sub = IdentityKeyPair::from_seed(&[9; 32]);
    let task = task_with(ChannelSpec {
        heartbeat_ms: 50,
        ..channel()
    });
    let (sub_io, mut exec_io) = duplex_pair(
        *sub.public().as_bytes(),
        *exec.public().as_bytes(),
        MAX_FRAME_BYTES,
        DEFAULT_DUPLEX_BUFFER,
    );

    let handle = StreamHandle::start(sub_io, &task, StreamOptions::default()).unwrap();
    // The executor side, as `StreamServer::handle` sets it up after the gate.
    let open = match exec_io.recv().await.unwrap() {
        Some(bytes) => match decode_frame(&bytes, Side::Submitter).unwrap() {
            Frame::Open(open) => open,
            other => panic!("expected Open, got {}", other.name()),
        },
        None => panic!("no Open frame"),
    };
    let request = request_digest(&open);
    let env = PolicyEnvelope::open(open.policy, open.policy_hash).unwrap();
    let ceilings = StreamCeilings {
        min_heartbeat_ms: 10,
        ..StreamCeilings::default()
    };
    let limits = ceilings.accept(&open.channel, open.timeout_ms).unwrap();
    assert_eq!(limits.heartbeat, Duration::from_millis(50));
    let machine = ExecutorMachine::new(
        ExecutorConfig {
            task_id: task.id,
            policy_hash: env.hash(),
            request,
            limits,
            local_peer: PeerId::from_public_key_bytes(exec.public().as_bytes()),
        },
        ChunkSigner::new(exec, open.task_id, env.hash(), request),
        Instant::now(),
    );
    let (mut port, driver_port) = stream_port(1);
    let plugin = async move {
        // 8 heartbeat intervals without a host call, holding the thread.
        std::thread::sleep(Duration::from_millis(400));
        port.yield_chunk(OUTPUT_HANDLE, b"done".to_vec()).await
    };
    let executor = tokio::spawn(driver::drive_executor(
        machine,
        exec_io,
        driver_port,
        plugin,
        None,
    ));

    let result = tokio::time::timeout(Duration::from_secs(10), handle.collect())
        .await
        .expect("the stream finishes");
    assert!(result.is_complete(), "{:?}", result.outcome);
    assert_eq!(result.bytes(), b"done");
    let report = tokio::time::timeout(Duration::from_secs(10), executor)
        .await
        .expect("the executor finishes")
        .unwrap();
    assert_eq!(report.outcome, Ok(()));
}

/// A submitter [`StreamHandle`] for `task` over a duplex, and the executor
/// end as `StreamServer::handle` sets it up after the gate: the machine and
/// the executor's half of the stream (its `Open` already read).
async fn driven_pair(
    task: &StreamingTask,
    ceilings: StreamCeilings,
    buffer: usize,
) -> (
    StreamHandle,
    ExecutorMachine,
    entangle_mesh_iroh::FramedStream,
) {
    use entangle_mesh_iroh::{duplex_pair, MAX_FRAME_BYTES};

    let exec = exec_key();
    let sub = IdentityKeyPair::from_seed(&[9; 32]);
    let (sub_io, mut exec_io) = duplex_pair(
        *sub.public().as_bytes(),
        *exec.public().as_bytes(),
        MAX_FRAME_BYTES,
        buffer,
    );
    let handle = StreamHandle::start(sub_io, task, StreamOptions::default()).unwrap();
    let open = match exec_io.recv().await.unwrap() {
        Some(bytes) => match decode_frame(&bytes, Side::Submitter).unwrap() {
            Frame::Open(open) => open,
            other => panic!("expected Open, got {}", other.name()),
        },
        None => panic!("no Open frame"),
    };
    let request = request_digest(&open);
    let env = PolicyEnvelope::open(open.policy, open.policy_hash).unwrap();
    let limits = ceilings.accept(&open.channel, open.timeout_ms).unwrap();
    let machine = ExecutorMachine::new(
        ExecutorConfig {
            task_id: task.id,
            policy_hash: env.hash(),
            request,
            limits,
            local_peer: PeerId::from_public_key_bytes(exec.public().as_bytes()),
        },
        ChunkSigner::new(exec, open.task_id, env.hash(), request),
        Instant::now(),
    );
    (handle, machine, exec_io)
}

/// A plugin that reads several input chunks before it yields anything must
/// get every buffered chunk (and the input's end) as soon as it asks for
/// it — not one per unrelated wake-up of the executor loop (the next
/// heartbeat, seconds away).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn buffered_input_reaches_a_plugin_that_reads_before_it_yields() {
    use entangle_host::{stream_port, ChunkResult, INPUT_HANDLE, OUTPUT_HANDLE};

    // 5 s heartbeats: nothing but the input itself may wake the loop here.
    let task = task_with(channel());
    let (mut handle, machine, exec_io) = driven_pair(
        &task,
        StreamCeilings::default(),
        entangle_mesh_iroh::DEFAULT_DUPLEX_BUFFER,
    )
    .await;
    let (mut port, driver_port) = stream_port(1);
    let plugin = async move {
        // Let the whole input arrive (and queue in the machine) first.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut got = Vec::new();
        loop {
            match port.next_chunk(INPUT_HANDLE).await {
                ChunkResult::Ok(bytes) => got.extend_from_slice(&bytes),
                ChunkResult::End => break,
                ChunkResult::Error(e) => return Err(e),
            }
        }
        port.yield_chunk(OUTPUT_HANDLE, got).await
    };
    let executor = tokio::spawn(driver::drive_executor(
        machine,
        exec_io,
        driver_port,
        plugin,
        None,
    ));
    for part in [&b"a"[..], b"b", b"c", b"d"] {
        handle.send_input(part.to_vec()).await.unwrap();
    }
    handle.finish_input().await.unwrap();

    let result = tokio::time::timeout(Duration::from_secs(3), handle.collect())
        .await
        .expect("the plugin gets its buffered input without waiting for a heartbeat");
    assert!(result.is_complete(), "{:?}", result.outcome);
    assert_eq!(result.bytes(), b"abcd");
    let report = tokio::time::timeout(Duration::from_secs(10), executor)
        .await
        .expect("the executor finishes")
        .unwrap();
    assert_eq!(report.outcome, Ok(()));
}

/// A transport half whose peer never reads: every write stays pending
/// forever. Dropping it drops the sender it holds, which is how a test sees
/// the writer let go of it.
struct StuckWriter(#[allow(dead_code)] tokio::sync::oneshot::Sender<()>);

impl tokio::io::AsyncWrite for StuckWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Pending
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }
}

/// A transport half whose peer never sends anything.
struct SilentReader;

impl tokio::io::AsyncRead for SilentReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }
}

/// An executor machine for a stream with no submitter attached, pinging
/// every `heartbeat`.
fn lone_executor(heartbeat: Duration) -> ExecutorMachine {
    executor_with(StreamLimits {
        max_chunk_bytes: 64,
        max_total_bytes: 1024,
        credit_window: 4,
        input_window: 4,
        heartbeat,
        credit_timeout: 5 * SEC,
        timeout: 60 * SEC,
    })
}

/// An executor machine under `limits`, with no submitter attached.
fn executor_with(limits: StreamLimits) -> ExecutorMachine {
    let env = PolicyEnvelope::seal(&IntegrityPolicy::None).unwrap();
    let task_id = task_with(channel()).id;
    ExecutorMachine::new(
        ExecutorConfig {
            task_id,
            policy_hash: env.hash(),
            request: [0; 32],
            limits,
            local_peer: PeerId::from_public_key_bytes(exec_key().public().as_bytes()),
        },
        ChunkSigner::new(exec_key(), *task_id.as_bytes(), env.hash(), [0; 32]),
        Instant::now(),
    )
}

/// A submitter that stops reading must not leave the executor's writer
/// task — the stream it owns and the frames queued for it — parked forever
/// once the stream is over.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_executor_whose_submitter_stops_reading_lets_go_of_its_writer() {
    use entangle_host::stream_port;
    use entangle_mesh_iroh::{FramedStream, MAX_FRAME_BYTES};

    let (writer_alive, writer_dropped) = tokio::sync::oneshot::channel::<()>();
    let io = FramedStream::from_parts(
        StuckWriter(writer_alive),
        SilentReader,
        *IdentityKeyPair::from_seed(&[9; 32]).public().as_bytes(),
        MAX_FRAME_BYTES,
    );
    let (_guest_port, driver_port) = stream_port(1);
    let plugin = std::future::pending::<Result<(), String>>();
    let report = tokio::time::timeout(
        Duration::from_secs(20),
        driver::drive_executor(
            lone_executor(Duration::from_millis(20)),
            io,
            driver_port,
            plugin,
            None,
        ),
    )
    .await
    .expect("the executor gives up on a submitter that never answers");
    assert_eq!(report.outcome, Err(StreamError::PeerLost { missed: 3 }));
    tokio::time::timeout(Duration::from_secs(2), writer_dropped)
        .await
        .expect("the writer let go of the stream when the executor returned")
        .unwrap_err();
}

/// A refusal is one best-effort `Error` frame: a peer that never reads (a
/// QUIC stack advertising a zero stream window, say) must not pin the
/// handler — and the stream it holds — forever. Nothing here needs the peer
/// to be authorized.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_to_a_peer_that_never_reads_is_bounded() {
    use entangle_mesh_iroh::{FramedStream, MAX_FRAME_BYTES};
    use std::sync::Arc;

    let kernel = Arc::new(
        entangle_runtime::Kernel::new(
            entangle_runtime::KernelConfig::default(),
            entangle_signing::Keyring::new(),
        )
        .unwrap(),
    );
    let nobody: crate::StaticAllowlist = std::iter::empty().collect();
    let server = StreamServer::new(kernel, Arc::new(nobody), exec_key());

    let (writer_alive, writer_dropped) = tokio::sync::oneshot::channel::<()>();
    let stranger = IdentityKeyPair::from_seed(&[42; 32]);
    let io = FramedStream::from_parts(
        StuckWriter(writer_alive),
        SilentReader,
        *stranger.public().as_bytes(),
        MAX_FRAME_BYTES,
    );
    let refused = tokio::time::timeout(Duration::from_secs(10), server.handle(io))
        .await
        .expect("refusing a peer that never reads gives up instead of hanging");
    assert!(
        matches!(
            refused,
            Err(StreamError::PeerAborted {
                reason: Reason::NotAuthorized,
                ..
            })
        ),
        "{refused:?}"
    );
    tokio::time::timeout(Duration::from_secs(2), writer_dropped)
        .await
        .expect("the refused stream is released")
        .unwrap_err();
}

/// Heartbeat frames are not queued behind data: a `Pong` answering a `Ping`
/// that arrives while full chunk frames wait for a slow link overtakes them,
/// so a healthy but bandwidth-bound stream is not declared lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pong_overtakes_chunks_queued_for_a_slow_link() {
    use entangle_host::{stream_port, OUTPUT_HANDLE};
    use entangle_mesh_iroh::{duplex_pair, MAX_FRAME_BYTES};

    // ~1 KiB of "link": the executor's writer blocks after a frame or two.
    let (mut sub_io, exec_io) = duplex_pair(
        *IdentityKeyPair::from_seed(&[9; 32]).public().as_bytes(),
        *exec_key().public().as_bytes(),
        MAX_FRAME_BYTES,
        1024,
    );
    let machine = executor_with(StreamLimits {
        max_chunk_bytes: 512,
        max_total_bytes: 1 << 20,
        credit_window: 32,
        input_window: 4,
        heartbeat: 60 * SEC,
        credit_timeout: 60 * SEC,
        timeout: 60 * SEC,
    });
    let (mut port, driver_port) = stream_port(1);
    let plugin = async move {
        for i in 0..32u8 {
            port.yield_chunk(OUTPUT_HANDLE, vec![i; 500]).await?;
        }
        Ok(())
    };
    let executor = tokio::spawn(driver::drive_executor(
        machine,
        exec_io,
        driver_port,
        plugin,
        None,
    ));
    // Let the executor fill every queue it has while nobody reads.
    tokio::time::sleep(Duration::from_millis(300)).await;
    sub_io
        .send(&encode_frame(&Frame::Ping { seq: 77, ts_ms: 1 }).unwrap())
        .await
        .unwrap();
    // …and let it answer: the Pong is queued while the chunks still wait.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut chunks_before_pong = 0;
    loop {
        let bytes = tokio::time::timeout(Duration::from_secs(10), sub_io.recv())
            .await
            .expect("a frame")
            .unwrap()
            .expect("the stream is open");
        match decode_frame(&bytes, Side::Executor).unwrap() {
            Frame::Pong { seq: 77, .. } => break,
            Frame::Chunk(_) => chunks_before_pong += 1,
            _ => {}
        }
    }
    assert!(
        chunks_before_pong <= 3,
        "the Pong waited behind {chunks_before_pong} queued chunks"
    );
    executor.abort();
}
