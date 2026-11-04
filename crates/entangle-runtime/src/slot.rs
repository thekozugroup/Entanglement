//! A loaded wasm plugin's instance and its lifecycle (spec §3.3 "instantiate
//! → … activate ↔ idle", §4.4 `[lifecycle]`): eager or lazy activation, and
//! teardown after `idle-timeout-secs` without a call.
//!
//! "Instance" here is what a loaded wasm plugin keeps resident between
//! calls: its compiled component, pre-instantiated against the host's linker
//! with its capability context attached ([`CompiledPlugin`]). Every call or
//! stream still runs in a fresh Wasmtime store created from it, so dropping
//! the instance loses no guest state — it frees the compiled code, and the
//! next call recreates it from the verified artifact bytes kept in memory
//! (through the AOT cache, so normally without recompiling).

use crate::errors::RuntimeError;
use crate::lifecycle::{LifecycleEvent, LifecyclePhase};
use entangle_host::{CapabilityContext, CompiledPlugin, HostEngine};
use entangle_ipc::{BusHandle, Envelope, Topic};
use entangle_manifest::lifecycle::{Activation, Lifecycle};
use entangle_observability::Registry;
use entangle_types::{plugin_id::PluginId, tier::Tier};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime};

/// Publishes lifecycle events; cheap to clone into background tasks.
#[derive(Clone)]
pub(crate) struct Events {
    bus: BusHandle<LifecycleEvent>,
    topic: Topic,
}

impl Events {
    pub(crate) fn new(bus: BusHandle<LifecycleEvent>, topic: Topic) -> Self {
        Self { bus, topic }
    }

    /// Publish `phase` for `plugin` (best effort: nothing is built when
    /// nobody subscribes; see `Kernel::emit`).
    pub(crate) fn emit(&self, plugin: &PluginId, effective_tier: Tier, phase: LifecyclePhase) {
        if self.bus.subscriber_count() == 0 {
            return;
        }
        let evt = LifecycleEvent {
            plugin: plugin.clone(),
            phase,
            effective_tier,
            at: SystemTime::now(),
        };
        let _ = self.bus.publish(Envelope::new(self.topic.clone(), evt));
    }
}

struct SlotState {
    /// The resident instance, when there is one.
    instance: Option<CompiledPlugin>,
    /// Calls and streams using the instance right now.
    active: usize,
    /// When the last call or stream ended (or the instance was created).
    last_used: Instant,
}

/// One loaded wasm plugin's instance slot.
pub(crate) struct WasmSlot {
    plugin_id: PluginId,
    tier: Tier,
    world: &'static str,
    lifecycle: Lifecycle,
    /// The verified artifact, kept when the instance can be dropped (lazy
    /// activation or an idle timeout) so it can be recreated without
    /// re-reading — and re-verifying — the package on disk.
    bytes: Option<Arc<[u8]>>,
    ctx: CapabilityContext,
    state: Mutex<SlotState>,
    /// Serialises instantiation, so concurrent first calls create one
    /// instance.
    activating: tokio::sync::Mutex<()>,
    /// Woken when a call ends or the slot is retired (the idle reaper).
    changed: Arc<tokio::sync::Notify>,
    /// Set once the plugin is unloaded or replaced: the reaper stops.
    retired: AtomicBool,
}

impl WasmSlot {
    /// A slot for `compiled` (already compiled and checked at load, with
    /// `ctx` attached). An eager plugin keeps it as its instance; a lazy one
    /// drops it and instantiates on first call.
    pub(crate) fn new(
        compiled: CompiledPlugin,
        ctx: CapabilityContext,
        bytes: &[u8],
        plugin_id: PluginId,
        tier: Tier,
        lifecycle: Lifecycle,
    ) -> Self {
        let world = compiled.world();
        let instance = (lifecycle.activation == Activation::Eager).then_some(compiled);
        Self {
            plugin_id,
            tier,
            world,
            lifecycle,
            bytes: lifecycle.can_be_torn_down().then(|| Arc::from(bytes)),
            ctx,
            state: Mutex::new(SlotState {
                instance,
                active: 0,
                last_used: Instant::now(),
            }),
            activating: tokio::sync::Mutex::new(()),
            changed: Arc::new(tokio::sync::Notify::new()),
            retired: AtomicBool::new(false),
        }
    }

    /// The `entangle:plugin` world the component implements.
    pub(crate) fn world(&self) -> &'static str {
        self.world
    }

    /// Whether an instance is resident right now.
    pub(crate) fn is_instantiated(&self) -> bool {
        self.state.lock().instance.is_some()
    }

    /// Stop the idle reaper (the plugin was unloaded or replaced).
    pub(crate) fn retire(&self) {
        self.retired.store(true, Ordering::Release);
        self.changed.notify_one();
    }

    fn take_resident(self: &Arc<Self>) -> Option<(CompiledPlugin, ActiveGuard)> {
        let mut st = self.state.lock();
        let instance = st.instance.clone()?;
        st.active += 1;
        Some((
            instance,
            ActiveGuard {
                slot: Arc::clone(self),
            },
        ))
    }

    /// The instance for one call or stream, creating it when there is none
    /// (publishing [`LifecyclePhase::Instantiated`]). The guard marks the
    /// plugin active until it is dropped: an active plugin is never torn
    /// down.
    pub(crate) async fn acquire(
        self: &Arc<Self>,
        engine: &HostEngine,
        aot: Option<&entangle_aot::AotCache>,
        events: &Events,
    ) -> Result<(CompiledPlugin, ActiveGuard), RuntimeError> {
        if let Some(found) = self.take_resident() {
            return Ok(found);
        }
        let _one_at_a_time = self.activating.lock().await;
        // Another call may have created it while this one waited.
        if let Some(found) = self.take_resident() {
            return Ok(found);
        }
        let Some(bytes) = &self.bytes else {
            // Unreachable by construction: only a slot that keeps its bytes
            // can be without an instance.
            return Err(RuntimeError::NotLoaded(self.plugin_id.clone()));
        };
        let (compiled, lookup) = CompiledPlugin::from_bytes_cached(
            engine,
            bytes,
            self.plugin_id.clone(),
            self.tier,
            aot,
        )?;
        tracing::debug!(plugin = %self.plugin_id, ?lookup, "instantiated on demand");
        let compiled = compiled.with_capabilities(self.ctx.clone());
        {
            let mut st = self.state.lock();
            st.instance = Some(compiled.clone());
            st.active += 1;
        }
        events.emit(&self.plugin_id, self.tier, LifecyclePhase::Instantiated);
        Ok((
            compiled,
            ActiveGuard {
                slot: Arc::clone(self),
            },
        ))
    }

    /// Drop the instance if it has been idle for the timeout and nothing
    /// uses it. Returns how long to wait before checking again (`None`:
    /// until something changes).
    fn reap(
        &self,
        timeout: Duration,
        events: &Events,
        metric: Option<&(Registry, String)>,
    ) -> Option<Duration> {
        let mut st = self.state.lock();
        if st.instance.is_none() || st.active > 0 {
            return None;
        }
        let idle = st.last_used.elapsed();
        if idle < timeout {
            return Some(timeout - idle);
        }
        st.instance = None;
        drop(st);
        tracing::debug!(plugin = %self.plugin_id, idle_secs = idle.as_secs(), "idle instance torn down");
        events.emit(&self.plugin_id, self.tier, LifecyclePhase::TornDown);
        if let Some((registry, label)) = metric {
            entangle_observability::catalog::plugin_idle_teardown(registry, label);
        }
        None
    }
}

impl Drop for WasmSlot {
    fn drop(&mut self) {
        // Let a waiting reaper notice the slot is gone.
        self.changed.notify_one();
    }
}

/// Marks a slot's instance in use (see [`WasmSlot::acquire`]).
pub(crate) struct ActiveGuard {
    slot: Arc<WasmSlot>,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        {
            let mut st = self.slot.state.lock();
            st.active = st.active.saturating_sub(1);
            st.last_used = Instant::now();
        }
        self.slot.changed.notify_one();
    }
}

/// Drop `slot`'s instance once it has been idle for its
/// `idle-timeout-secs` (no-op without one). The task ends when the slot is
/// retired or dropped; it holds only a weak reference.
pub(crate) fn spawn_idle_reaper(
    slot: &Arc<WasmSlot>,
    events: Events,
    metric: Option<(Registry, String)>,
) {
    let Some(timeout) = slot.lifecycle.idle_timeout else {
        return;
    };
    let weak: Weak<WasmSlot> = Arc::downgrade(slot);
    let changed = Arc::clone(&slot.changed);
    tokio::spawn(async move {
        loop {
            let wait = {
                let Some(slot) = weak.upgrade() else { return };
                if slot.retired.load(Ordering::Acquire) {
                    return;
                }
                slot.reap(timeout, &events, metric.as_ref())
            };
            // A permit stored by a `notify_one` since the check is consumed
            // at once, so no wake-up is lost. Without one, wake at least
            // every `timeout` to notice a dropped slot.
            let nap = wait.unwrap_or(timeout);
            tokio::select! {
                () = changed.notified() => {}
                () = tokio::time::sleep(nap) => {}
            }
        }
    });
}
