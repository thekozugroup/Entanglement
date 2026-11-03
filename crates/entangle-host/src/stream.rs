//! [`LoadedStreamPlugin`] — a compiled component of the `stream-plugin`
//! world — and the [`StreamPort`] its chunks flow through (spec §7.1).
//!
//! # The world
//!
//! A stream plugin exports `start-stream(input) -> result<stream-handle, …>`
//! and imports `entangle:plugin/stream`:
//!
//! * `yield-chunk(0, bytes)` puts one chunk on the **output** stream
//!   ([`OUTPUT_HANDLE`]). The call blocks until the protocol driver has
//!   actually sent the chunk — i.e. while the submitter has granted no
//!   credit — and returns an error once the stream can no longer carry
//!   chunks (cancelled, lost, stalled past its timeout, over a size cap).
//! * `next-chunk(1)` reads the next chunk of the **input** stream
//!   ([`INPUT_HANDLE`]) the submitter sends while the task runs.
//!
//! Returning `ok(0)` from `start-stream` ends the output stream normally;
//! returning `err(..)` fails it.
//!
//! # Who decides
//!
//! This module only moves bytes between the guest and a driver. It knows
//! nothing about credit, heartbeats or signatures: the driver on the other
//! side of the [`StreamPortDriver`] (the scheduler's stream executor) owns
//! the protocol and acknowledges each chunk only once it is on the wire, so
//! the guest's `yield-chunk` blocking *is* the protocol's backpressure.

use crate::bindings::entangle::plugin::types::PluginError;
use crate::engine::{HostEngine, EPOCH_TICK_MS};
use crate::errors::HostError;
use crate::plugin::{classify_call_error, classify_instantiate_error};
use crate::state::{HostState, ResourceLimits};
use entangle_types::{plugin_id::PluginId, tier::Tier};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use wasmtime::component::{Component, InstancePre};
use wasmtime::Store;

/// Generated host bindings for the `entangle:plugin@0.1.0` `stream-plugin`
/// world. The interfaces it shares with the `plugin` world are mapped onto
/// [`crate::bindings`], so one [`HostState`] implementation serves both.
#[allow(missing_docs)] // generated code
pub mod bindings {
    wasmtime::component::bindgen!({
        // Relative to this crate's Cargo.toml (crates/entangle-host/).
        path: "../entangle-wit/wit",
        world: "stream-plugin",
        imports: { default: async },
        exports: { default: async },
        with: {
            "entangle:plugin/logging": crate::bindings::entangle::plugin::logging,
            "entangle:plugin/capability": crate::bindings::entangle::plugin::capability,
            "entangle:plugin/host-info": crate::bindings::entangle::plugin::host_info,
            "entangle:plugin/types": crate::bindings::entangle::plugin::types,
        },
    });
}

pub use bindings::entangle::plugin::stream::ChunkResult;

/// The handle of a streaming invocation's output stream (`yield-chunk`).
pub const OUTPUT_HANDLE: u64 = 0;
/// The handle of a streaming invocation's input stream (`next-chunk`).
pub const INPUT_HANDLE: u64 = 1;

/// Extra wall-clock slack for the tokio backstop beyond the epoch deadline;
/// mirrors the one-shot path.
const TIMEOUT_BACKSTOP_SLACK_MS: u64 = 250;

/// Message a guest sees when the driver side of its port is gone.
const STREAM_CLOSED: &str = "stream closed";

/// One chunk a guest yielded, waiting for the driver to send or refuse it.
#[derive(Debug)]
pub struct PluginChunk {
    /// The chunk's bytes, exactly as the guest yielded them.
    pub bytes: Vec<u8>,
    /// Completes the guest's pending `yield-chunk` call.
    pub ack: ChunkAck,
}

/// Completes a guest's pending `yield-chunk` call.
///
/// Dropping it without calling either method fails the call with
/// `"stream closed"`, so a driver that gives up never leaves a guest
/// blocked forever.
#[derive(Debug)]
pub struct ChunkAck(oneshot::Sender<Result<(), String>>);

impl ChunkAck {
    /// The chunk is on the wire: `yield-chunk` returns `ok`.
    pub fn sent(self) {
        let _ = self.0.send(Ok(()));
    }

    /// The chunk will never be sent: `yield-chunk` returns `error(reason)`.
    pub fn refuse(self, reason: impl Into<String>) {
        let _ = self.0.send(Err(reason.into()));
    }
}

/// One item of a streaming invocation's input stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamInput {
    /// The next input chunk.
    Chunk(Vec<u8>),
    /// The submitter finished sending input.
    End,
    /// The stream closed before the input ended.
    Error(String),
}

/// The guest-facing end of a streaming invocation's channels, attached to
/// its store for the duration of one `start-stream` call.
#[derive(Debug)]
pub struct StreamPort {
    chunks: mpsc::Sender<PluginChunk>,
    input: mpsc::Receiver<StreamInput>,
    input_ended: bool,
}

/// The driver-facing end of a [`StreamPort`].
#[derive(Debug)]
pub struct StreamPortDriver {
    /// Chunks the guest yields, one at a time: the guest is blocked until the
    /// driver answers through [`PluginChunk::ack`].
    pub chunks: mpsc::Receiver<PluginChunk>,
    /// Feeds the guest's input stream. Bounded: a driver that sends faster
    /// than the guest reads waits (the protocol's input credit keeps it from
    /// having more than the window buffered anyway).
    pub input: mpsc::Sender<StreamInput>,
}

/// Create a connected [`StreamPort`] / [`StreamPortDriver`] pair whose input
/// channel buffers at most `input_buffer` items.
pub fn stream_port(input_buffer: usize) -> (StreamPort, StreamPortDriver) {
    // Capacity 1 on the chunk side: the guest has at most one chunk in
    // flight, and its `yield-chunk` stays blocked until that chunk is acked.
    let (chunk_tx, chunk_rx) = mpsc::channel(1);
    let (input_tx, input_rx) = mpsc::channel(input_buffer.max(1));
    (
        StreamPort {
            chunks: chunk_tx,
            input: input_rx,
            input_ended: false,
        },
        StreamPortDriver {
            chunks: chunk_rx,
            input: input_tx,
        },
    )
}

impl StreamPort {
    /// `yield-chunk(handle, chunk)`: what the guest import does, also usable
    /// directly by a native (in-process) producer.
    pub async fn yield_chunk(&mut self, handle: u64, bytes: Vec<u8>) -> Result<(), String> {
        if handle != OUTPUT_HANDLE {
            return Err(format!(
                "unknown output stream handle {handle} (the output stream is {OUTPUT_HANDLE})"
            ));
        }
        let (tx, rx) = oneshot::channel();
        self.chunks
            .send(PluginChunk {
                bytes,
                ack: ChunkAck(tx),
            })
            .await
            .map_err(|_| STREAM_CLOSED.to_owned())?;
        rx.await.unwrap_or_else(|_| Err(STREAM_CLOSED.to_owned()))
    }

    /// `next-chunk(handle)`: what the guest import does, also usable
    /// directly by a native (in-process) producer.
    pub async fn next_chunk(&mut self, handle: u64) -> ChunkResult {
        if handle != INPUT_HANDLE {
            return ChunkResult::Error(format!(
                "unknown input stream handle {handle} (the input stream is {INPUT_HANDLE})"
            ));
        }
        if self.input_ended {
            return ChunkResult::End;
        }
        match self.input.recv().await {
            Some(StreamInput::Chunk(bytes)) => ChunkResult::Ok(bytes),
            Some(StreamInput::End) => {
                self.input_ended = true;
                ChunkResult::End
            }
            Some(StreamInput::Error(e)) => ChunkResult::Error(e),
            None => ChunkResult::Error(STREAM_CLOSED.to_owned()),
        }
    }
}

impl bindings::entangle::plugin::stream::Host for HostState {
    async fn yield_chunk(&mut self, handle: u64, chunk: Vec<u8>) -> Result<(), String> {
        match self.stream.as_mut() {
            Some(port) => port.yield_chunk(handle, chunk).await,
            None => Err("this invocation has no output stream".to_owned()),
        }
    }

    async fn next_chunk(&mut self, handle: u64) -> ChunkResult {
        match self.stream.as_mut() {
            Some(port) => port.next_chunk(handle).await,
            None => ChunkResult::Error("this invocation has no input stream".to_owned()),
        }
    }
}

/// The outcome of a completed `start-stream` call.
#[derive(Clone, Debug)]
pub struct StreamRunResult {
    /// Log lines the plugin emitted, `(level, message)`.
    pub log_lines: Vec<(String, String)>,
}

/// A compiled `stream-plugin` component, ready to instantiate once per
/// stream.
#[derive(Clone)]
pub struct LoadedStreamPlugin {
    pre: bindings::StreamPluginPre<HostState>,
    plugin_id: PluginId,
    effective_tier: Tier,
}

impl std::fmt::Debug for LoadedStreamPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedStreamPlugin")
            .field("plugin_id", &self.plugin_id)
            .field("effective_tier", &self.effective_tier)
            .finish_non_exhaustive()
    }
}

impl LoadedStreamPlugin {
    /// Compile `bytes` as a `stream-plugin` component.
    ///
    /// [`HostError::Compile`] for bytes that are not a component;
    /// [`HostError::Instantiate`] for a component without a `start-stream`
    /// export or with imports the host does not provide.
    pub fn from_bytes(
        engine: &HostEngine,
        bytes: &[u8],
        plugin_id: PluginId,
        effective_tier: Tier,
    ) -> Result<Self, HostError> {
        let component = Component::from_binary(engine.engine(), bytes)?;
        let instance_pre = engine
            .linker()
            .instantiate_pre(&component)
            .map_err(|e| HostError::Instantiate(e.into()))?;
        Self::from_instance_pre(instance_pre, plugin_id, effective_tier)
    }

    pub(crate) fn from_instance_pre(
        instance_pre: InstancePre<HostState>,
        plugin_id: PluginId,
        effective_tier: Tier,
    ) -> Result<Self, HostError> {
        let pre = bindings::StreamPluginPre::new(instance_pre)
            .map_err(|e| HostError::Instantiate(e.into()))?;
        Ok(Self {
            pre,
            plugin_id,
            effective_tier,
        })
    }

    /// Instantiate the component in a fresh store, attach `port`, and run
    /// `start-stream(input)` to completion.
    ///
    /// Time and memory are bounded as for a one-shot call: an epoch deadline
    /// of `timeout_ms` plus a tokio backstop ([`HostError::Timeout`]), and
    /// `limits` ([`HostError::ResourceExhausted`]). The backstop also covers
    /// a guest parked in `yield-chunk` waiting for credit. An `err(..)`
    /// result is [`HostError::PluginReturnedError`], as is an `ok(h)` naming
    /// a handle other than [`OUTPUT_HANDLE`].
    pub async fn run_stream(
        &self,
        engine: &HostEngine,
        input: &[u8],
        port: StreamPort,
        timeout_ms: u64,
        limits: ResourceLimits,
    ) -> Result<StreamRunResult, HostError> {
        let mut state = HostState::with_limits(self.plugin_id.clone(), self.effective_tier, limits);
        state.stream = Some(port);
        let mut store = Store::new(engine.engine(), state);
        store.limiter(|s| &mut s.limits);
        store.set_epoch_deadline(timeout_ms.div_ceil(EPOCH_TICK_MS).max(1));

        let run = async {
            let plugin = self
                .pre
                .instantiate_async(&mut store)
                .await
                .map_err(|e| classify_instantiate_error(e.into(), timeout_ms))?;
            plugin
                .call_start_stream(&mut store, input)
                .await
                .map_err(|e| classify_call_error(e.into(), timeout_ms))
        };

        let backstop = Duration::from_millis(timeout_ms.saturating_add(TIMEOUT_BACKSTOP_SLACK_MS));
        let outcome = match tokio::time::timeout(backstop, run).await {
            Ok(result) => result?,
            Err(_elapsed) => return Err(HostError::Timeout(timeout_ms)),
        };
        // Release the port now so the driver sees the channels close even if
        // the caller keeps the result around.
        store.data_mut().stream = None;
        match outcome {
            Ok(OUTPUT_HANDLE) => {}
            Ok(other) => {
                return Err(HostError::PluginReturnedError(format!(
                    "start-stream returned handle {other}; a stream plugin ends its output \
                     stream by returning {OUTPUT_HANDLE}"
                )))
            }
            Err(e) => return Err(HostError::PluginReturnedError(plugin_error_text(e))),
        }
        let log_lines = std::mem::take(&mut store.data_mut().log_buffer);
        Ok(StreamRunResult { log_lines })
    }

    /// Returns the plugin identifier.
    pub fn plugin_id(&self) -> &PluginId {
        &self.plugin_id
    }

    /// Returns the effective capability tier for this plugin.
    pub fn effective_tier(&self) -> Tier {
        self.effective_tier
    }
}

/// Render a guest `plugin-error` the way the one-shot path does.
pub(crate) fn plugin_error_text(e: PluginError) -> String {
    match e {
        PluginError::InvalidInput(s) => format!("invalid-input: {s}"),
        PluginError::ResourceExhausted(s) => format!("resource-exhausted: {s}"),
        PluginError::CapabilityDenied(s) => format!("capability-denied: {s}"),
        PluginError::Internal(s) => format!("internal: {s}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn yield_chunk_waits_for_the_driver_and_reports_its_verdict() {
        let (mut port, mut driver) = stream_port(4);
        let guest = tokio::spawn(async move {
            let first = port.yield_chunk(OUTPUT_HANDLE, b"a".to_vec()).await;
            let second = port.yield_chunk(OUTPUT_HANDLE, b"b".to_vec()).await;
            (first, second)
        });
        let c = driver.chunks.recv().await.unwrap();
        assert_eq!(c.bytes, b"a");
        c.ack.sent();
        let c = driver.chunks.recv().await.unwrap();
        c.ack.refuse("cancelled");
        let (first, second) = guest.await.unwrap();
        assert_eq!(first, Ok(()));
        assert_eq!(second, Err("cancelled".to_owned()));
    }

    #[tokio::test]
    async fn a_dropped_ack_or_driver_fails_the_yield_instead_of_hanging() {
        let (mut port, mut driver) = stream_port(4);
        let guest = tokio::spawn(async move { port.yield_chunk(OUTPUT_HANDLE, vec![1]).await });
        drop(driver.chunks.recv().await.unwrap());
        assert_eq!(guest.await.unwrap(), Err(STREAM_CLOSED.to_owned()));

        let (mut port, driver) = stream_port(4);
        drop(driver);
        assert_eq!(
            port.yield_chunk(OUTPUT_HANDLE, vec![1]).await,
            Err(STREAM_CLOSED.to_owned())
        );
    }

    #[tokio::test]
    async fn handles_are_checked() {
        let (mut port, _driver) = stream_port(4);
        assert!(port.yield_chunk(INPUT_HANDLE, vec![]).await.is_err());
        assert!(matches!(
            port.next_chunk(OUTPUT_HANDLE).await,
            ChunkResult::Error(_)
        ));
    }

    #[tokio::test]
    async fn next_chunk_reads_input_then_end_then_stays_ended() {
        let (mut port, driver) = stream_port(4);
        driver
            .input
            .send(StreamInput::Chunk(b"x".to_vec()))
            .await
            .unwrap();
        driver.input.send(StreamInput::End).await.unwrap();
        assert!(matches!(port.next_chunk(INPUT_HANDLE).await, ChunkResult::Ok(b) if b == b"x"));
        assert!(matches!(
            port.next_chunk(INPUT_HANDLE).await,
            ChunkResult::End
        ));
        drop(driver);
        assert!(matches!(
            port.next_chunk(INPUT_HANDLE).await,
            ChunkResult::End
        ));
    }

    #[tokio::test]
    async fn input_closed_without_end_is_an_error() {
        let (mut port, driver) = stream_port(4);
        drop(driver);
        assert!(matches!(
            port.next_chunk(INPUT_HANDLE).await,
            ChunkResult::Error(e) if e == STREAM_CLOSED
        ));
    }

    #[test]
    fn a_one_shot_component_is_not_a_stream_plugin() {
        let engine = HostEngine::new().unwrap();
        let bytes = wat::parse_str("(component)").unwrap();
        let id: PluginId = "aabbccddeeff00112233445566778899/s@0.1.0".parse().unwrap();
        assert!(matches!(
            LoadedStreamPlugin::from_bytes(&engine, &bytes, id, Tier::Pure),
            Err(HostError::Instantiate(_))
        ));
    }
}
