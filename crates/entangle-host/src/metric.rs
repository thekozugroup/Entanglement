//! Submitter-only execution of a pairwise distance component with no host imports.
use crate::{
    engine::EPOCH_TICK_MS,
    plugin::{classify_call_error, classify_instantiate_error},
    state::ResourceLimits,
    HostEngine, HostError,
};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use wasmtime::{
    component::{Component, Linker},
    Store, StoreLimits,
};

#[allow(missing_docs)]
mod bindings {
    wasmtime::component::bindgen!({
        path: "../entangle-wit/integrity", world: "comparator",
        imports: { default: async }, exports: { default: async },
    });
}

/// A compiled comparator. No guest instance exists until a pair is compared.
#[derive(Clone)]
pub struct MetricComponent {
    pre: bindings::ComparatorPre<StoreLimits>,
    engine: HostEngine,
    instances: Arc<AtomicU64>,
}

impl MetricComponent {
    /// Verify the ABI and prelink in an empty linker (no WASI, filesystem or network).
    pub fn compile(engine: &HostEngine, bytes: &[u8]) -> Result<Self, HostError> {
        let component = Component::from_binary(engine.engine(), bytes)?;
        let linker = Linker::<StoreLimits>::new(engine.engine());
        let pre = bindings::ComparatorPre::new(linker.instantiate_pre(&component)?)?;
        Ok(Self {
            pre,
            engine: engine.clone(),
            instances: Arc::default(),
        })
    }

    /// Count successful guest instantiations on this kernel.
    pub fn instantiations(&self) -> u64 {
        self.instances.load(Ordering::Relaxed)
    }

    /// Run exactly one fresh bounded guest for this pair.
    pub async fn compare(&self, a: &[u8], b: &[u8], timeout_ms: u64) -> Result<f64, HostError> {
        let mut store = Store::new(
            self.engine.engine(),
            ResourceLimits::default().to_store_limits(),
        );
        store.limiter(|limits| limits);
        store.set_epoch_deadline(timeout_ms.div_ceil(EPOCH_TICK_MS).max(1));
        let run = async {
            let instance = self
                .pre
                .instantiate_async(&mut store)
                .await
                .map_err(|e| classify_instantiate_error(e, timeout_ms))?;
            self.instances.fetch_add(1, Ordering::Relaxed);
            tracing::debug!("instantiated submitter integrity metric");
            let distance = instance
                .entangle_integrity_metric()
                .call_compare(&mut store, a, b)
                .await
                .map_err(|e| classify_call_error(e, timeout_ms))?;
            if !distance.is_finite() || distance < 0.0 {
                return Err(HostError::PluginReturnedError(
                    "invalid metric distance".into(),
                ));
            }
            Ok(distance)
        };
        tokio::time::timeout(Duration::from_millis(timeout_ms.saturating_add(100)), run)
            .await
            .map_err(|_| HostError::Timeout(timeout_ms))?
    }
}
