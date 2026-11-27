//! Locally trusted, signed comparisons used by semantic-equivalence submissions.
use crate::RuntimeError;
use entangle_host::metric::MetricComponent;
use entangle_types::plugin_id::PluginId;
use std::sync::Arc;
use tokio::sync::RwLock;

/// The signed manifest's build world for integrity comparator packages.
pub const METRIC_WORLD: &str = "entangle:integrity/comparator@0.1.0";

/// A submitter-local metric bound to its publisher and exact component bytes.
#[derive(Clone)]
pub struct VerifiedMetric {
    /// BLAKE3 digest of the signed Wasm component.
    pub cid: [u8; 32],
    /// Raw Ed25519 public key of the signer.
    pub publisher: [u8; 32],
    pub(crate) id: PluginId,
    pub(crate) component: MetricComponent,
    pub(crate) invocation_gate: Arc<RwLock<bool>>,
}

impl VerifiedMetric {
    /// Compare one eligible pair on the submitter, enforcing unload and the task deadline.
    pub async fn compare(&self, a: &[u8], b: &[u8], timeout_ms: u64) -> Result<f64, RuntimeError> {
        let active = self.invocation_gate.read().await;
        if !*active {
            return Err(RuntimeError::NotLoaded(self.id.clone()));
        }
        Ok(self.component.compare(a, b, timeout_ms).await?)
    }

    /// Number of real Wasmtime instances created for comparisons of this package.
    pub fn instantiations(&self) -> u64 {
        self.component.instantiations()
    }
}
