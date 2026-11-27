//! Authenticated, credit-controlled streaming tasks over the scheduler QUIC ALPN.

use entangle_mesh_iroh::{MeshDuplex, MeshFrameReader, MeshFrameWriter, MeshIrohError};
use entangle_signing::{IdentityKeyPair, IdentityPublicKey, Signature};
use entangle_types::{
    peer_id::PeerId,
    task::{IntegrityPolicy, StreamingTask, TaskId},
};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::{sync::mpsc, time::Instant};

mod client;
mod worker;
pub use client::StreamingClient;
pub(crate) use worker::serve_worker;
pub use worker::{StreamExecutor, StreamOutput};

pub(crate) const OPEN: &[u8] = b"ENTANGLE-STREAM-1\0";
const MAX_INPUT: usize = 1024 * 1024;
const MAX_METADATA: usize = 65536;
const CHUNK_HEADER: usize = 81;
const HEARTBEAT: Duration = Duration::from_secs(5);
const LOST: Duration = Duration::from_secs(15);
const ACCEPT: u8 = 1;
const CHUNK: u8 = 2;
const CREDIT: u8 = 3;
const PING: u8 = 4;
const PONG: u8 = 5;
const STALLED: u8 = 6;
const END: u8 = 7;
const FAILURE: u8 = 8;
const MAX_CHUNKS: u64 = 65_536;

/// Stable receiver and worker failure categories.
#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    /// Replicated/attested integrity policies have no streaming verifier.
    #[error("invalid integrity policy for streaming; use TrustedExecutor")]
    InvalidIntegrityForStreaming,
    /// Resource or channel parameters were outside supported bounds.
    #[error("invalid streaming task: {0}")]
    Invalid(String),
    /// Bytes, order or signature do not match the authenticated worker.
    #[error("bad streaming chunk signature")]
    BadChunkSignature,
    /// The authenticated worker lost its local pairing or trust could not be verified.
    #[error("stream worker is no longer authorized")]
    WorkerNotAuthorized,
    /// No valid heartbeat response for three successive intervals.
    #[error("stream peer lost")]
    PeerLost,
    /// The worker or submitter rejected a protocol frame or the invocation.
    #[error("stream protocol: {0}")]
    Protocol(String),
    /// A data chunk exceeds the declared maximum size or is empty.
    #[error("stream chunk size exceeded")]
    ChunkSizeExceeded,
    /// The cumulative payload exceeds the declared cap.
    #[error("stream total bytes exceeded")]
    TotalBytesExceeded,
    /// Authenticated transport failed.
    #[error(transparent)]
    Transport(#[from] MeshIrohError),
}

/// A verified chunk. The detached signature also supports independent offline attribution.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedChunk {
    /// Zero-based chunk sequence.
    pub seq: u64,
    /// Executor Unix timestamp in milliseconds.
    pub timestamp_ms: u64,
    /// Actual payload.
    pub bytes: Vec<u8>,
    /// Detached Ed25519 signature.
    pub signature: Vec<u8>,
}
impl SignedChunk {
    fn message(task: TaskId, seq: u64, ts: u64, bytes: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(96);
        m.extend_from_slice(b"entangle/stream/chunk/1\0");
        m.extend_from_slice(task.as_bytes());
        m.extend_from_slice(&seq.to_be_bytes());
        m.extend_from_slice(&ts.to_be_bytes());
        m.extend_from_slice(&Sha256::digest(bytes));
        m
    }
    /// Verify source, task and sequence with the expected authenticated executor's key.
    pub fn verify(
        &self,
        key: &IdentityPublicKey,
        task: TaskId,
        expected: u64,
    ) -> Result<(), StreamError> {
        let sig =
            Signature::from_bytes(&self.signature).map_err(|_| StreamError::BadChunkSignature)?;
        if self.seq != expected {
            return Err(StreamError::BadChunkSignature);
        }
        key.verify(
            &Self::message(task, self.seq, self.timestamp_ms, &self.bytes),
            &sig,
        )
        .map_err(|_| StreamError::BadChunkSignature)
    }
    fn encode(
        key: &IdentityKeyPair,
        task: TaskId,
        seq: u64,
        bytes: &[u8],
    ) -> Result<Vec<u8>, StreamError> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StreamError::Protocol("invalid executor clock".into()))?
            .as_millis() as u64;
        let sig = key.sign(&Self::message(task, seq, ts, bytes));
        let mut out = Vec::with_capacity(CHUNK_HEADER + bytes.len());
        out.push(CHUNK);
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&ts.to_be_bytes());
        out.extend_from_slice(sig.as_bytes());
        out.extend_from_slice(bytes);
        Ok(out)
    }
    fn decode(frame: &[u8]) -> Result<Self, StreamError> {
        if frame.len() <= CHUNK_HEADER || frame[0] != CHUNK {
            return Err(StreamError::Protocol("invalid chunk".into()));
        }
        Ok(Self {
            seq: u64::from_be_bytes(frame[1..9].try_into().unwrap()),
            timestamp_ms: u64::from_be_bytes(frame[9..17].try_into().unwrap()),
            signature: frame[17..CHUNK_HEADER].to_vec(),
            bytes: frame[CHUNK_HEADER..].to_vec(),
        })
    }
}

/// Typed stream observations, in order.
#[derive(Debug)]
pub enum StreamEvent {
    /// Signature and all cumulative bounds were verified before delivery.
    Chunk(SignedChunk),
    /// Credits remained exhausted until the configured stall timeout.
    Stalled {
        /// Number of completed chunks.
        chunks: u64,
        /// Verified bytes delivered.
        bytes: u64,
    },
    /// Clean successful terminal frame.
    Finished,
}

/// Validate before routing, dialing or invoking a plugin.
pub fn validate(
    task: &StreamingTask,
    input_bytes: usize,
    worker: Option<PeerId>,
) -> Result<(), StreamError> {
    match &task.integrity {
        IntegrityPolicy::None => {}
        IntegrityPolicy::TrustedExecutor { allowlist }
            if worker.is_none_or(|p| allowlist.contains(&p)) => {}
        IntegrityPolicy::TrustedExecutor { .. } => {
            return Err(StreamError::Invalid(
                "executor is not trusted by task".into(),
            ))
        }
        _ => return Err(StreamError::InvalidIntegrityForStreaming),
    }
    let c = &task.channel;
    if !(1..=1024 * 1024).contains(&c.max_chunk_bytes)
        || !(1..=256 * 1024 * 1024).contains(&c.max_total_bytes)
        || !(1..=256).contains(&c.credit_window)
        || c.heartbeat_ms != 5000
        || !(1..=1_800_000).contains(&task.timeout_ms)
        || input_bytes > MAX_INPUT
        || !task.resources.cpu_cores.is_finite()
        || task.resources.cpu_cores < 0.0
    {
        return Err(StreamError::Invalid(
            "channel, resource, timeout, or input bound exceeded".into(),
        ));
    }
    Ok(())
}
fn validate_chunk_size(task: &StreamingTask, len: usize, received: u64) -> Result<(), StreamError> {
    let len = len as u64;
    if len == 0 || len > task.channel.max_chunk_bytes {
        return Err(StreamError::ChunkSizeExceeded);
    }
    if len > task.channel.max_total_bytes.saturating_sub(received) {
        return Err(StreamError::TotalBytesExceeded);
    }
    Ok(())
}

pub(crate) fn opening(task: &StreamingTask, input: &[u8]) -> Result<Vec<u8>, StreamError> {
    validate(task, input.len(), None)?;
    let meta = serde_json::to_vec(task).map_err(|e| StreamError::Invalid(e.to_string()))?;
    if meta.len() > MAX_METADATA {
        return Err(StreamError::Invalid("metadata too long".into()));
    }
    let mut out = OPEN.to_vec();
    out.extend_from_slice(&(meta.len() as u32).to_be_bytes());
    out.extend_from_slice(&meta);
    out.extend_from_slice(input);
    Ok(out)
}
fn parse_open(bytes: &[u8]) -> Result<(StreamingTask, &[u8]), StreamError> {
    let data = bytes
        .strip_prefix(OPEN)
        .ok_or_else(|| StreamError::Invalid("stream version".into()))?;
    let (len, rest) = data
        .split_at_checked(4)
        .ok_or_else(|| StreamError::Invalid("short opening".into()))?;
    let size = u32::from_be_bytes(len.try_into().unwrap()) as usize;
    if size > MAX_METADATA {
        return Err(StreamError::Invalid("metadata too long".into()));
    }
    let (meta, input) = rest
        .split_at_checked(size)
        .ok_or_else(|| StreamError::Invalid("short metadata".into()))?;
    let task = serde_json::from_slice(meta)
        .map_err(|e| StreamError::Invalid(format!("task metadata: {e}")))?;
    Ok((task, input))
}

struct Frames {
    writer: MeshFrameWriter,
    inbox: mpsc::Receiver<Result<Vec<u8>, MeshIrohError>>,
    reader: tokio::task::JoinHandle<()>,
}
impl Frames {
    fn new(stream: MeshDuplex, max: usize) -> Self {
        let (writer, mut reader): (MeshFrameWriter, MeshFrameReader) = stream.split();
        let (tx, inbox) = mpsc::channel(1);
        let reader = tokio::spawn(async move {
            loop {
                let r = reader.receive(max).await;
                let end = r.is_err();
                if tx.send(r).await.is_err() || end {
                    break;
                }
            }
        });
        Self {
            writer,
            inbox,
            reader,
        }
    }
    async fn send(&mut self, frame: &[u8]) -> Result<(), StreamError> {
        tokio::time::timeout(LOST, self.writer.send(frame))
            .await
            .map_err(|_| StreamError::PeerLost)??;
        Ok(())
    }
}
impl Drop for Frames {
    fn drop(&mut self) {
        self.reader.abort();
    }
}
struct Heartbeat {
    last_pong: Instant,
    next: Instant,
    seq: u64,
    ack: u64,
}
impl Heartbeat {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            last_pong: now,
            next: now,
            seq: 0,
            ack: 0,
        }
    }
    fn ping(&mut self, now: Instant) -> Result<[u8; 16], StreamError> {
        if now.duration_since(self.last_pong) >= LOST {
            return Err(StreamError::PeerLost);
        }
        self.next = now + HEARTBEAT;
        self.seq += 1;
        let mut frame = [0u8; 16];
        frame[0] = PING;
        frame[8..].copy_from_slice(&self.seq.to_be_bytes());
        Ok(frame)
    }
    async fn control(&mut self, frame: &[u8], io: &mut Frames) -> Result<bool, StreamError> {
        if !matches!(frame.first(), Some(&PING) | Some(&PONG)) {
            return Ok(false);
        }
        if frame.len() != 16 {
            return Err(StreamError::Protocol("invalid heartbeat".into()));
        }
        if frame[0] == PING {
            let mut pong = frame.to_vec();
            pong[0] = PONG;
            io.send(&pong).await?;
        } else {
            let seq = u64::from_be_bytes(frame[8..].try_into().unwrap());
            if seq > self.seq || seq <= self.ack {
                return Err(StreamError::Protocol("unexpected pong".into()));
            }
            self.ack = seq;
            self.last_pong = Instant::now();
        }
        Ok(true)
    }
}
fn frame_received(frame: Option<Result<Vec<u8>, MeshIrohError>>) -> Result<Vec<u8>, StreamError> {
    frame
        .ok_or(StreamError::PeerLost)?
        .map_err(|_| StreamError::PeerLost)
}
