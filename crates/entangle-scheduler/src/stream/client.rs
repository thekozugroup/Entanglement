use super::*;
use crate::remote::PeerAddressBook;
use entangle_mesh_iroh::MeshConn;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

struct WorkerTrust {
    peer: PeerId,
    addresses: Arc<dyn PeerAddressBook>,
    revoked: AtomicBool,
}

impl WorkerTrust {
    async fn check(&self) -> Result<(), StreamError> {
        if self.revoked.load(Ordering::Acquire) {
            return Err(StreamError::WorkerNotAuthorized);
        }
        let addresses = self.addresses.clone();
        let peer = self.peer;
        let permitted = tokio::task::spawn_blocking(move || addresses.permits_stream(&peer))
            .await
            .unwrap_or(false);
        if !permitted {
            self.revoked.store(true, Ordering::Release);
        }
        if self.revoked.load(Ordering::Acquire) {
            return Err(StreamError::WorkerNotAuthorized);
        }
        Ok(())
    }
}

/// A live submitter-side stream. Heartbeats continue when a consumer withholds
/// credit or spends time processing chunks. Dropping the handle cancels the stream.
pub struct StreamingClient {
    pub(crate) reservation: Option<crate::worker::Reservation>,
    credits: mpsc::Sender<u32>,
    events: mpsc::Receiver<Result<StreamEvent, StreamError>>,
    driver: tokio::task::JoinHandle<()>,
    trust: Arc<WorkerTrust>,
    pending: Option<StreamEvent>,
}
impl StreamingClient {
    pub(crate) async fn start(
        conn: MeshConn,
        task: StreamingTask,
        input: &[u8],
        addresses: Arc<dyn PeerAddressBook>,
    ) -> Result<Self, StreamError> {
        let peer = conn.remote_peer_id();
        validate(&task, input.len(), Some(peer))?;
        let key = IdentityPublicKey::from_bytes(&conn.remote_public_key())
            .map_err(|_| StreamError::BadChunkSignature)?;
        let trust = Arc::new(WorkerTrust {
            peer,
            addresses,
            revoked: AtomicBool::new(false),
        });
        trust.check().await?;
        let mut frames = Frames::new(
            conn.open_stream(&opening(&task, input)?).await?,
            CHUNK_HEADER + task.channel.max_chunk_bytes.max(512) as usize,
        );
        let response = tokio::time::timeout(LOST, frames.inbox.recv())
            .await
            .map_err(|_| StreamError::PeerLost)?;
        let response = frame_received(response)?;
        if response != [ACCEPT] {
            return Err(stream_failure(&response));
        }
        let (credits, mut outgoing) = mpsc::channel(8);
        let (events_tx, events) = mpsc::channel(task.channel.credit_window as usize + 3);
        let driver_trust = trust.clone();
        let driver = tokio::spawn(async move {
            let result = run(
                &task,
                key,
                &mut frames,
                &mut outgoing,
                &events_tx,
                &driver_trust,
            )
            .await;
            conn.close();
            if let Err(error) = result {
                let _ = events_tx.send(Err(error)).await;
            }
        });
        Ok(Self {
            reservation: None,
            credits,
            events,
            driver,
            trust,
            pending: None,
        })
    }
    /// Wait for a verified chunk, a stall notification, or stream completion.
    pub async fn next(&mut self) -> Result<StreamEvent, StreamError> {
        if self.trust.revoked.load(Ordering::Acquire) {
            return Err(StreamError::WorkerNotAuthorized);
        }
        if self.pending.is_none() {
            self.pending = Some(self.events.recv().await.ok_or(StreamError::PeerLost)??);
        }
        // Holding the event in the handle makes delivery cancellation-safe if
        // the local RPC read times out while checking the authoritative store.
        if matches!(self.pending, Some(StreamEvent::Chunk(_))) {
            self.trust.check().await.inspect_err(|_| {
                self.driver.abort();
                self.events.close();
            })?;
        }
        Ok(self.pending.take().expect("received an event above"))
    }
    /// Replenish processing capacity after consuming chunks.
    pub async fn credit(&self, add: u32) -> Result<(), StreamError> {
        if add == 0 {
            return Err(StreamError::Invalid("credit must be positive".into()));
        }
        self.credits
            .send(add)
            .await
            .map_err(|_| StreamError::PeerLost)
    }
}
impl Drop for StreamingClient {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
fn stream_failure(frame: &[u8]) -> StreamError {
    if let Some(error) = frame.strip_prefix(&[FAILURE]) {
        if error == b"total-bytes" {
            return StreamError::TotalBytesExceeded;
        }
        if error == b"chunk-size" {
            return StreamError::ChunkSizeExceeded;
        }
        if error == b"peer-lost" {
            return StreamError::PeerLost;
        }
        return StreamError::Protocol(String::from_utf8_lossy(error).into_owned());
    }
    StreamError::Protocol("unexpected stream response".into())
}
async fn run(
    task: &StreamingTask,
    key: IdentityPublicKey,
    frames: &mut Frames,
    outgoing: &mut mpsc::Receiver<u32>,
    events: &mpsc::Sender<Result<StreamEvent, StreamError>>,
    trust: &WorkerTrust,
) -> Result<(), StreamError> {
    let mut hb = Heartbeat::new();
    let mut seq = 0u64;
    let mut total = 0u64;
    let mut credits = task.channel.credit_window;
    // QUIC can announce STOP_SENDING on the control half before the END
    // receipt is delivered on the independent data half.
    let mut drain_until = None;
    loop {
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(drain_until.unwrap_or(hb.next)), if drain_until.is_some() => {
                return Err(StreamError::PeerLost);
            }
            _ = tokio::time::sleep_until(hb.next), if drain_until.is_none() => {
                trust.check().await?;
                if frames.send(&hb.ping(Instant::now())?).await.is_err() {
                    drain_until = Some(Instant::now() + LOST);
                }
            }
            add = outgoing.recv(), if drain_until.is_none() => {
                let add = add.ok_or(StreamError::PeerLost)?;
                credits = credits.checked_add(add).filter(|n| *n <= task.channel.credit_window)
                    .ok_or_else(|| StreamError::Protocol("credit exceeds negotiated window".into()))?;
                let mut grant = vec![CREDIT];
                grant.extend_from_slice(&add.to_be_bytes());
                if frames.send(&grant).await.is_err() {
                    drain_until = Some(Instant::now() + LOST);
                }
            }
            frame = frames.inbox.recv() => {
                let frame = frame_received(frame)?;
                if frame.first() == Some(&PING) && drain_until.is_some() { continue; }
                match hb.control(&frame, frames).await {
                    Ok(true) => continue,
                    Err(StreamError::Transport(_)) => {
                        drain_until.get_or_insert_with(|| Instant::now() + LOST);
                        continue;
                    }
                    Err(error) => return Err(error),
                    Ok(false) => {}
                }
                let event = match frame.first() {
                    Some(&CHUNK) => {
                        if credits == 0 || seq >= MAX_CHUNKS {
                            return Err(StreamError::Protocol("chunk beyond negotiated credit/count".into()));
                        }
                        let chunk = SignedChunk::decode(&frame)?;
                        validate_chunk_size(task, chunk.bytes.len(), total)?;
                        chunk.verify(&key, task.id, seq)?;
                        total += chunk.bytes.len() as u64;
                        credits -= 1;
                        seq += 1;
                        StreamEvent::Chunk(chunk)
                    }
                    Some(&STALLED | &END) if frame.len() == 17 => {
                        if frame[1..9] != seq.to_be_bytes() || frame[9..] != total.to_be_bytes() {
                            return Err(StreamError::Protocol("invalid stream receipt".into()));
                        }
                        if frame[0] == END {
                            let _ = events.send(Ok(StreamEvent::Finished)).await;
                            return Ok(());
                        }
                        StreamEvent::Stalled { chunks:seq, bytes:total }
                    }
                    _ => return Err(stream_failure(&frame)),
                };
                events.try_send(Ok(event)).map_err(|_| StreamError::Protocol("consumer queue full".into()))?;
            }
        }
    }
}
