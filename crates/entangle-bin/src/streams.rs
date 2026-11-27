//! Bounded pull-based UDS sessions. One small queue per session, at most one
//! chunk per RPC response. Abandoned local clients release their worker slot.
use entangle_rpc::{StreamHandle, StreamOpenParams, StreamRead};
use entangle_scheduler::{stream::StreamEvent, Dispatcher};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot, Semaphore};

enum Command {
    Read(oneshot::Sender<Result<StreamRead, String>>),
    Cancel,
}
#[derive(Clone)]
pub(crate) struct Sessions {
    slots: Arc<Semaphore>,
    entries: Arc<Mutex<HashMap<String, mpsc::Sender<Command>>>>,
}
impl Default for Sessions {
    fn default() -> Self {
        Self {
            slots: Arc::new(Semaphore::new(32)),
            entries: Arc::default(),
        }
    }
}
impl Sessions {
    pub(crate) async fn handle(
        &self,
        method: &str,
        params: serde_json::Value,
        dispatcher: &Dispatcher,
    ) -> Result<serde_json::Value, String> {
        if method == "compute/stream/open" {
            let p: StreamOpenParams = serde_json::from_value(params).map_err(|e| e.to_string())?;
            let slot = self
                .slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| "too many stream sessions".to_string())?;
            let (peer, mut stream) = dispatcher
                .dispatch_stream(p.task, &p.input)
                .await
                .map_err(|e| e.to_string())?;
            let session = entangle_types::task::TaskId::new_v4().to_string();
            let id = session.clone();
            let entries = self.entries.clone();
            let (tx, mut rx) = mpsc::channel(1);
            entries.lock().unwrap().insert(id.clone(), tx);
            tokio::spawn(async move {
                let _slot = slot;
                while let Ok(Some(Command::Read(reply))) =
                    tokio::time::timeout(Duration::from_secs(60), rx.recv()).await
                {
                    let result =
                        match tokio::time::timeout(Duration::from_secs(2), stream.next()).await {
                            Err(_) => Ok(StreamRead::Waiting),
                            Ok(Ok(StreamEvent::Finished)) => Ok(StreamRead::Finished),
                            Ok(Ok(StreamEvent::Stalled { .. })) => Ok(StreamRead::Stalled),
                            Ok(Ok(StreamEvent::Chunk(c))) => {
                                // A worker may already have sent EOF; the signed event is still deliverable.
                                let _ = stream.credit(1).await;
                                Ok(StreamRead::Chunk {
                                    seq: c.seq,
                                    timestamp_ms: c.timestamp_ms,
                                    signature: c.signature,
                                    bytes: c.bytes,
                                })
                            }
                            Ok(Err(e)) => Err(e.to_string()),
                        };
                    let done = matches!(result, Ok(StreamRead::Finished) | Err(_));
                    if reply.send(result).is_err() || done {
                        break;
                    }
                }
                entries.lock().unwrap().remove(&id);
            });
            return serde_json::to_value(StreamHandle {
                session,
                executor: peer,
            })
            .map_err(|e| e.to_string());
        }
        let id = params
            .as_str()
            .ok_or_else(|| "expected stream session ID".to_string())?;
        let tx = self
            .entries
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| "stream session not found".to_string())?;
        if method == "compute/stream/close" {
            tx.send(Command::Cancel)
                .await
                .map_err(|_| "stream closed")?;
            return Ok(serde_json::Value::Null);
        }
        let (reply, response) = oneshot::channel();
        tx.try_send(Command::Read(reply))
            .map_err(|_| "another stream read is pending".to_string())?;
        let event = response.await.map_err(|_| "stream closed".to_string())??;
        serde_json::to_value(event).map_err(|e| e.to_string())
    }
}
