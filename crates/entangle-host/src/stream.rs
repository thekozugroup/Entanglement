//! Host for the progressive output WIT world. Each guest yield awaits consumer credit.
use entangle_types::{plugin_id::PluginId, tier::Tier};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};
use wasmtime::{component::Component, Store};

use crate::{
    engine::EPOCH_TICK_MS,
    plugin::{classify_call_error, classify_instantiate_error},
    HostEngine, HostError, HostState,
};

#[allow(missing_docs)]
pub(crate) mod bindings {
    wasmtime::component::bindgen!({
        path: "../entangle-wit/wit", world: "stream-plugin",
        imports: { default: async }, exports: { default: async },
        with: {
            "entangle:plugin/logging": crate::bindings::entangle::plugin::logging,
            "entangle:plugin/capability": crate::bindings::entangle::plugin::capability,
            "entangle:plugin/host-info": crate::bindings::entangle::plugin::host_info,
            "entangle:plugin/types": crate::bindings::entangle::plugin::types,
        },
    });
}

type WriteFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;
/// State private to one worker invocation. No routing decision is made from a guest handle.
pub(crate) struct Output {
    write: Box<dyn Fn(Vec<u8>) -> WriteFuture + Send + Sync>,
    handle: Option<u64>,
    remaining: u64,
    max_total: u64,
    clock: tokio::sync::watch::Sender<ComputeBudget>,
    max_chunk: u32,
    failure: Option<HostError>,
}

// Only acknowledged downstream writes suspend the active-compute deadline.
#[derive(Clone, Copy)]
struct ComputeBudget {
    left: Duration,
    running_since: Option<Instant>,
}

impl ComputeBudget {
    fn remaining(self) -> Duration {
        self.left.saturating_sub(
            self.running_since
                .map_or(Duration::ZERO, |start| start.elapsed()),
        )
    }

    fn pause(&mut self) {
        self.left = self.remaining();
        self.running_since = None;
    }

    fn resume(&mut self) {
        self.running_since = Some(Instant::now());
    }
}

async fn budget_exhausted(mut budget: tokio::sync::watch::Receiver<ComputeBudget>) {
    loop {
        let state = *budget.borrow_and_update();
        if state.running_since.is_some() {
            let left = state.remaining();
            if left.is_zero() {
                return;
            }
            tokio::select! {
                _ = tokio::time::sleep(left) => continue,
                changed = budget.changed() => if changed.is_err() { return; },
            }
        } else if budget.changed().await.is_err() {
            return;
        }
    }
}

impl bindings::entangle::plugin::stream::Host for HostState {
    async fn yield_chunk(&mut self, handle: u64, chunk: Vec<u8>) -> Result<(), String> {
        let stream = self
            .stream_output
            .as_mut()
            .ok_or_else(|| "output stream unavailable".to_owned())?;
        if let Some(error) = &stream.failure {
            return Err(error.to_string());
        }
        let size = chunk.len() as u64;
        let result = if *stream.handle.get_or_insert(handle) != handle {
            Err(HostError::PluginReturnedError(
                "stream handle changed".into(),
            ))
        } else if size == 0 || size > u64::from(stream.max_chunk) {
            Err(HostError::StreamChunkSizeExceeded {
                limit: stream.max_chunk,
                actual: size,
            })
        } else if size > stream.remaining {
            Err(HostError::StreamTotalBytesExceeded {
                limit: stream.max_total,
                actual: (stream.max_total - stream.remaining).saturating_add(size),
            })
        } else {
            stream.remaining -= size;
            stream.clock.send_modify(ComputeBudget::pause);
            let result = (stream.write)(chunk)
                .await
                .map_err(HostError::PluginReturnedError);
            stream.clock.send_modify(ComputeBudget::resume);
            result
        };
        result.map_err(|error| {
            let message = error.to_string();
            stream.failure = Some(error);
            message
        })
    }
    async fn next_chunk(
        &mut self,
        _handle: u64,
    ) -> bindings::entangle::plugin::stream::ChunkResult {
        bindings::entangle::plugin::stream::ChunkResult::Error(
            "input streaming unavailable on an output-only task".into(),
        )
    }
}

/// A prelinked streaming component that can run multiple independent invocations.
#[derive(Clone)]
pub struct StreamingComponent {
    pre: Arc<bindings::StreamPluginPre<HostState>>,
    plugin: PluginId,
    tier: Tier,
}

/// Limits negotiated before a streaming worker begins execution.
#[derive(Clone, Copy)]
pub struct StreamLimits {
    /// Active execution budget, excluding waits for acknowledged output writes.
    pub timeout_ms: u64,
    /// Maximum payload per yield.
    pub max_chunk_bytes: u32,
    /// Maximum output across all yields.
    pub max_total_bytes: u64,
}

impl StreamingComponent {
    /// Check the component and prelink its streaming ABI without running guest code.
    pub fn compile(
        engine: &HostEngine,
        bytes: &[u8],
        plugin: PluginId,
        tier: Tier,
    ) -> Result<Self, HostError> {
        let component = Component::from_binary(engine.engine(), bytes)?;
        let pre = bindings::StreamPluginPre::new(engine.linker().instantiate_pre(&component)?)?;
        Ok(Self {
            pre: Arc::new(pre),
            plugin,
            tier,
        })
    }

    /// Run a progressive guest and await the downstream acknowledgement for each chunk.
    pub async fn run<F, Fut>(
        &self,
        engine: &HostEngine,
        input: &[u8],
        limits: StreamLimits,
        emit: F,
    ) -> Result<(), HostError>
    where
        F: Fn(Vec<u8>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let timeout_ms = limits.timeout_ms;
        if timeout_ms == 0
            || !(1..=1024 * 1024).contains(&limits.max_chunk_bytes)
            || !(1..=256 * 1024 * 1024).contains(&limits.max_total_bytes)
        {
            return Err(HostError::PluginReturnedError(
                "invalid stream limits".into(),
            ));
        }
        let mut state = HostState::new(self.plugin.clone(), self.tier);
        let (clock, budget) = tokio::sync::watch::channel(ComputeBudget {
            left: Duration::from_millis(timeout_ms),
            running_since: Some(Instant::now()),
        });
        state.stream_output = Some(Output {
            clock,
            write: Box::new(move |chunk| Box::pin(emit(chunk))),
            handle: None,
            remaining: limits.max_total_bytes,
            max_total: limits.max_total_bytes,
            max_chunk: limits.max_chunk_bytes,
            failure: None,
        });
        let mut store = Store::new(engine.engine(), state);
        store.limiter(|s| &mut s.limits);
        let epoch_budget = budget.clone();
        store.set_epoch_deadline(timeout_ms.div_ceil(EPOCH_TICK_MS).max(1));
        store.epoch_deadline_callback(move |_| {
            let remaining = epoch_budget.borrow().remaining();
            if remaining.is_zero() {
                return Err(wasmtime::Trap::Interrupt.into());
            }
            Ok(wasmtime::UpdateDeadline::Continue(
                (remaining.as_millis() as u64)
                    .div_ceil(EPOCH_TICK_MS)
                    .max(1),
            ))
        });
        let run = async {
            let instance = self
                .pre
                .instantiate_async(&mut store)
                .await
                .map_err(|e| classify_instantiate_error(e, timeout_ms))?;
            let returned = instance.call_start_stream(&mut store, input).await;
            let output = store
                .data_mut()
                .stream_output
                .take()
                .expect("output bound for this invocation");
            if let Some(error) = output.failure {
                return Err(error);
            }
            let handle = returned
                .map_err(|error| classify_call_error(error, timeout_ms))?
                .map_err(|error| HostError::PluginReturnedError(format!("{error:?}")))?;
            if output.handle.is_some_and(|bound| bound != handle) {
                return Err(HostError::PluginReturnedError(
                    "returned stream handle differs from yielded handle".into(),
                ));
            }
            Ok(())
        };
        tokio::select! {
            result = run => result,
            _ = budget_exhausted(budget) => Err(HostError::Timeout(timeout_ms)),
        }
    }
}
