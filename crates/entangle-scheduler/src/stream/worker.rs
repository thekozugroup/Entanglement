use super::*;
use entangle_runtime::Kernel;
use std::sync::Arc;

/// A progressive producer pushes individual nonempty chunks into this bounded
/// channel. Sending naturally waits while the receiver withholds credit.
#[derive(Clone)]
pub struct StreamOutput {
    sender: mpsc::Sender<PendingChunk>,
    active_timeout_ms: u64,
}
struct PendingChunk {
    bytes: Vec<u8>,
    accepted: tokio::sync::oneshot::Sender<()>,
}
impl StreamOutput {
    /// Yield a chunk and wait until authenticated transport credit permitted
    /// the worker to write it. Cancelling the stream releases blocked producers.
    pub async fn send_chunk(&self, bytes: Vec<u8>) -> Result<(), String> {
        let (accepted, ack) = tokio::sync::oneshot::channel();
        self.sender
            .send(PendingChunk { bytes, accepted })
            .await
            .map_err(|_| "stream closed".to_owned())?;
        ack.await.map_err(|_| "stream closed".to_owned())
    }
}

/// Host or guest adapter producing incremental output for a streaming invocation.
#[async_trait::async_trait]
pub trait StreamExecutor: Send + Sync {
    /// Advertise adapters that support streams and have no one-shot entry point.
    async fn streaming_plugins(&self) -> Vec<entangle_types::plugin_id::PluginId> {
        Vec::new()
    }

    /// Produce chunks within the declared limits and close the channel at EOF.
    async fn produce(
        &self,
        task: StreamingTask,
        input: Vec<u8>,
        output: StreamOutput,
    ) -> Result<(), String>;
}

#[async_trait::async_trait]
impl StreamExecutor for Kernel {
    async fn produce(
        &self,
        task: StreamingTask,
        input: Vec<u8>,
        output: StreamOutput,
    ) -> Result<(), String> {
        let timeout_ms = output.active_timeout_ms;
        if self.is_stream_plugin(&task.plugin) {
            return self
                .invoke_stream(
                    &task.plugin,
                    &input,
                    timeout_ms,
                    task.channel.max_chunk_bytes as u32,
                    task.channel.max_total_bytes,
                    move |chunk| {
                        let output = output.clone();
                        async move { output.send_chunk(chunk).await }
                    },
                )
                .await
                .map_err(|e| match e {
                    entangle_runtime::RuntimeError::StreamTotalBytesExceeded { .. } => {
                        "total-bytes".into()
                    }
                    entangle_runtime::RuntimeError::StreamChunkSizeExceeded { .. } => {
                        "chunk-size".into()
                    }
                    other => other.to_string(),
                });
        }
        let bytes = self
            .invoke(&task.plugin, &input, timeout_ms)
            .await
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > task.channel.max_total_bytes {
            return Err("total-bytes".into());
        }
        for chunk in bytes.chunks(task.channel.max_chunk_bytes as usize) {
            output.send_chunk(chunk.to_vec()).await?;
        }
        Ok(())
    }
}

pub(crate) async fn serve_worker(
    req: entangle_mesh_iroh::MeshRequest,
    signer: Arc<IdentityKeyPair>,
    executor: Arc<dyn StreamExecutor>,
    worker: PeerId,
    allowed: Arc<dyn crate::remote::PeerAllowlist>,
    metrics: &entangle_runtime::Kernel,
    active_timeout_ms: u64,
) -> Result<(), MeshIrohError> {
    let mut req = req;
    let payload = req.take_payload();
    let from = req.peer_id();
    let mut frames = Frames::new(req.into_stream(), 64);
    let result = async {
        let (task, input) = parse_open(&payload)?;
        validate(&task, input.len(), Some(worker))?;
        if PeerId::from_public_key_bytes(signer.public().as_bytes()) != worker {
            return Err(StreamError::Protocol(
                "worker signing identity mismatch".into(),
            ));
        }
        frames.send(&[ACCEPT]).await?;
        run(
            task,
            input.to_vec(),
            &mut frames,
            signer,
            executor,
            from,
            allowed,
            metrics,
            active_timeout_ms,
        )
        .await
    }
    .await;
    if let Err(e) = result {
        let mut reply = vec![FAILURE];
        let text = match e {
            StreamError::ChunkSizeExceeded => "chunk-size".into(),
            StreamError::TotalBytesExceeded => "total-bytes".into(),
            StreamError::PeerLost => "peer-lost".into(),
            other => other.to_string(),
        };
        reply.extend(text.bytes().take(256));
        let _ = frames.send(&reply).await;
    }
    frames.writer.finish()
}
fn receipt(tag: u8, seq: u64, bytes: u64) -> Vec<u8> {
    let mut f = vec![tag];
    f.extend_from_slice(&seq.to_be_bytes());
    f.extend_from_slice(&bytes.to_be_bytes());
    f
}
#[allow(clippy::too_many_arguments)]
async fn run(
    task: StreamingTask,
    input: Vec<u8>,
    frames: &mut Frames,
    signer: Arc<IdentityKeyPair>,
    executor: Arc<dyn StreamExecutor>,
    from: PeerId,
    allow: Arc<dyn crate::remote::PeerAllowlist>,
    kernel: &Kernel,
    active_timeout_ms: u64,
) -> Result<(), StreamError> {
    let (tx, mut chunks) = mpsc::channel(1);
    let mut producers = tokio::task::JoinSet::new();
    let work = task.clone();
    producers.spawn(async move {
        executor
            .produce(
                work,
                input,
                StreamOutput {
                    sender: tx,
                    active_timeout_ms,
                },
            )
            .await
    });
    let mut credits = task.channel.credit_window;
    let mut seq = 0u64;
    let mut total = 0u64;
    let stall = Duration::from_millis(task.timeout_ms);
    let mut deadline = None;
    let mut stalled = false;
    let mut hb = Heartbeat::new();
    let mut produced = false;
    let mut output_closed = false;
    // Charge producer execution and backend I/O. Once the producer yields a chunk,
    // it awaits our acknowledgement. Only that delivery interval suspends its budget.
    let mut remaining = Duration::from_millis(active_timeout_ms);
    let mut active_deadline = Instant::now() + remaining;
    let mut pending: Option<PendingChunk> = None;
    loop {
        if credits > 0 {
            if let Some(PendingChunk { bytes, accepted }) = pending.take() {
                frames
                    .send(&SignedChunk::encode(&signer, task.id, seq, &bytes)?)
                    .await?;
                seq += 1;
                total += bytes.len() as u64;
                credits -= 1;
                if credits == 0 {
                    deadline = Some(Instant::now() + stall);
                }
                active_deadline = Instant::now() + remaining;
                let _ = accepted.send(());
            }
        }
        if pending.is_none() && produced && chunks.is_empty() {
            frames.send(&receipt(END, seq, total)).await?;
            return Ok(());
        }
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(active_deadline), if pending.is_none() => {
                return Err(StreamError::Protocol("stream execution exceeded the worker active-time limit".into()));
            }
            _ = tokio::time::sleep_until(hb.next) => {
                let allow = allow.clone();
                let trusted = tokio::task::spawn_blocking(move || allow.is_authorized(&from))
                    .await.unwrap_or(false);
                if !trusted {
                    return Err(StreamError::Protocol("peer authorization revoked".into()));
                }
                frames.send(&hb.ping(Instant::now())?).await?;
            }
            _ = tokio::time::sleep_until(deadline.unwrap_or(hb.next)), if deadline.is_some() => {
                if stalled {
                    return Err(StreamError::Protocol("credit stall cancelled".into()));
                }
                stalled = true;
                deadline = Some(Instant::now() + stall);
                tracing::info!(task_id = %task.id, peer = %from, chunks = seq, bytes = total, "StalledEvent");
                kernel.metrics().inc_counter(
                    "entangle_scheduler_streams_stalled_total", "Streams stalled awaiting credit",
                    &[("peer_id", &from.to_hex())], 1.0,
                );
                frames.send(&receipt(STALLED, seq, total)).await?;
            }
            joined = producers.join_next(), if !produced => {
                producer_result(joined)?;
                produced = true;
            }
            frame = frames.inbox.recv() => {
                let frame = frame_received(frame)?;
                if hb.control(&frame, frames).await? { continue; }
                if frame.len() != 5 || frame[0] != CREDIT {
                    return Err(StreamError::Protocol("invalid credit frame".into()));
                }
                let add = u32::from_be_bytes(frame[1..].try_into().unwrap());
                credits = credits.checked_add(add)
                    .filter(|n| add > 0 && *n <= task.channel.credit_window)
                    .ok_or_else(|| StreamError::Protocol("excess credit".into()))?;
                stalled = false;
                deadline = None;
            }
            chunk = chunks.recv(), if pending.is_none() && !output_closed => {
                let Some(PendingChunk { bytes, accepted }) = chunk else {
                    output_closed = true;
                    continue;
                };
                if bytes.is_empty() || seq >= MAX_CHUNKS {
                    return Err(StreamError::Protocol("invalid stream chunk/count".into()));
                }
                validate_chunk_size(&task, bytes.len(), total)?;
                remaining = active_deadline.saturating_duration_since(Instant::now());
                pending = Some(PendingChunk { bytes, accepted });
            }
        }
    }
}

fn producer_result(
    result: Option<Result<Result<(), String>, tokio::task::JoinError>>,
) -> Result<(), StreamError> {
    match result {
        Some(Ok(Ok(()))) => Ok(()),
        Some(Ok(Err(e))) if e == "chunk-size" => Err(StreamError::ChunkSizeExceeded),
        Some(Ok(Err(e))) if e == "total-bytes" => Err(StreamError::TotalBytesExceeded),
        Some(Ok(Err(e))) => Err(StreamError::Protocol(e)),
        _ => Err(StreamError::Protocol("stream producer terminated".into())),
    }
}
