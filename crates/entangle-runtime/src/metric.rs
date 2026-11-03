//! [`MetricRegistry`] — the submitter's set of verified metric components.
//!
//! `IntegrityPolicy::SemanticEquivalent` compares replica outputs with a
//! signed Wasm component implementing `entangle:integrity/metric@0.1.0`
//! (spec §7.5). The registry is where such components enter a node:
//!
//! 1. **Load** — [`MetricRegistry::load_from_dir`] reads a signed package
//!    (`entangle.toml` + `plugin.wasm` + `plugin.wasm.sig`, the same layout as
//!    any plugin), verifies the signature against the node's keyring, binds the
//!    signer to the manifest's publisher, refuses anything that asks for more
//!    than tier 2 or any capability, and compiles it. The result is a
//!    [`MetricRef`] pinning plugin id, publisher key and artifact BLAKE3.
//! 2. **Check** — [`MetricRegistry::check_trusted`] is the §7.5 Rule 2 gate:
//!    a reference whose publisher key is not on *this node's* keyring is
//!    refused with [`IntegrityError::MetricNotInKeyring`] (ATC-INT-2).
//! 3. **Compare** — [`MetricRegistry::compare`] re-checks trust (a key can be
//!    removed after load), instantiates the component once, and enforces the
//!    metric contract on the result.
//!
//! Only the submitter ever holds one of these with metrics in it: workers run
//! the task, never the metric (§7.5 Rule 3, verifier-locality).

use crate::integrity::IntegrityError;
use crate::loader::PluginPackage;
use entangle_host::metric::DEFAULT_METRIC_TIMEOUT_MS;
use entangle_host::state::ResourceLimits;
use entangle_host::{HostEngine, LoadedMetric};
use entangle_manifest::validate::validate;
use entangle_manifest::Runtime;
use entangle_signing::{verify_artifact, Keyring, SignatureBundle, VerificationError};
use entangle_types::plugin_id::PluginId;
use entangle_types::task::MetricRef;
use entangle_types::tier::Tier;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// Default memory ceiling for one metric instantiation (256 MiB).
///
/// Two replica outputs are copied into guest memory, each at most the task's
/// `max_output_bytes` (16 MiB by default), so this leaves ample room while
/// still bounding the verifier.
pub const DEFAULT_METRIC_MEMORY_BYTES: usize = 256 * 1024 * 1024;

/// A verified, compiled metric component.
#[derive(Clone, Debug)]
pub struct MetricEntry {
    /// What the component is, pinned.
    pub reference: MetricRef,
    /// The compiled component.
    pub metric: LoadedMetric,
}

/// The node's verified metric components, keyed by artifact BLAKE3.
///
/// Cheap to share behind an `Arc`; all methods take `&self`.
pub struct MetricRegistry {
    keyring: Arc<RwLock<Keyring>>,
    owner: String,
    /// Created on first load so a node that never verifies a
    /// `SemanticEquivalent` task never pays for a second engine.
    engine: Mutex<Option<HostEngine>>,
    metrics: RwLock<HashMap<[u8; 32], MetricEntry>>,
    timeout_ms: u64,
    limits: ResourceLimits,
}

impl std::fmt::Debug for MetricRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricRegistry")
            .field("owner", &self.owner)
            .field("metrics", &self.metrics.read().len())
            .field("timeout_ms", &self.timeout_ms)
            .finish_non_exhaustive()
    }
}

impl MetricRegistry {
    /// An empty registry that trusts exactly the keys in `keyring`.
    ///
    /// `owner` labels this node in the metric trace events (the scheduler
    /// passes its peer id).
    pub fn new(keyring: Arc<RwLock<Keyring>>, owner: impl Into<String>) -> Self {
        Self {
            keyring,
            owner: owner.into(),
            engine: Mutex::new(None),
            metrics: RwLock::new(HashMap::new()),
            timeout_ms: DEFAULT_METRIC_TIMEOUT_MS,
            limits: ResourceLimits {
                memory_bytes: DEFAULT_METRIC_MEMORY_BYTES,
                ..ResourceLimits::default()
            },
        }
    }

    /// Override the per-comparison wall-clock budget and memory ceiling.
    #[must_use]
    pub fn with_limits(mut self, timeout_ms: u64, limits: ResourceLimits) -> Self {
        self.timeout_ms = timeout_ms;
        self.limits = limits;
        self
    }

    /// The owner label carried in trace events.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Load and verify a signed metric package from `dir`.
    ///
    /// Idempotent: loading the same artifact again returns the same reference.
    pub fn load_from_dir(&self, dir: &Path) -> Result<MetricRef, IntegrityError> {
        let label = dir.display().to_string();
        let load_err = |reason: String| IntegrityError::MetricLoad {
            source_path: label.clone(),
            reason,
        };
        let pkg = PluginPackage::from_directory(dir).map_err(|e| load_err(e.to_string()))?;
        let sig_text = std::fs::read_to_string(&pkg.signature_path)
            .map_err(|e| load_err(format!("reading {}: {e}", pkg.signature_path.display())))?;
        let bundle: SignatureBundle =
            toml::from_str(&sig_text).map_err(|e| load_err(format!("signature bundle: {e}")))?;
        self.load_package(&label, &pkg.bytes, &pkg.manifest_bytes, &bundle)
    }

    /// Load and verify a metric package from memory.
    ///
    /// `label` names the source in errors. The checks, in order: manifest
    /// parses and validates; the plugin is `runtime = "wasm"`, declares at most
    /// tier 2 and no capabilities (a metric gets none); the signature verifies
    /// against this node's keyring (an unknown signer is
    /// [`IntegrityError::MetricNotInKeyring`]); the signer is the publisher the
    /// manifest names; the bytes compile as an `entangle:integrity/metric`
    /// component.
    pub fn load_package(
        &self,
        label: &str,
        wasm: &[u8],
        manifest: &[u8],
        bundle: &SignatureBundle,
    ) -> Result<MetricRef, IntegrityError> {
        let load_err = |reason: String| IntegrityError::MetricLoad {
            source_path: label.to_owned(),
            reason,
        };

        // Manifest: parsed from the same bytes the signature covers.
        let text =
            std::str::from_utf8(manifest).map_err(|_| load_err("manifest is not UTF-8".into()))?;
        let raw: entangle_manifest::schema::Manifest =
            toml::from_str(text).map_err(|e| load_err(format!("manifest: {e}")))?;
        let manifest_v = validate(raw).map_err(|e| load_err(format!("manifest: {e}")))?;
        let plugin_id = manifest_v.plugin_id.clone();
        if manifest_v.runtime != Runtime::Wasm {
            return Err(load_err(format!(
                "{plugin_id} is not a wasm component; metrics run in the wasm sandbox"
            )));
        }
        if manifest_v.effective_tier > Tier::Sandboxed || !manifest_v.capabilities.is_empty() {
            return Err(load_err(format!(
                "{plugin_id} declares tier {} with {} capabilities; a metric runs at tier 2 \
                 with no filesystem, no network and no capabilities",
                manifest_v.effective_tier as u8,
                manifest_v.capabilities.len()
            )));
        }

        // Signature against *this node's* keyring.
        let entry = {
            let kr = self.keyring.read();
            match verify_artifact(wasm, manifest, bundle, &kr) {
                Ok(entry) => entry.clone(),
                Err(VerificationError::UnknownPublisher) => {
                    return Err(IntegrityError::MetricNotInKeyring {
                        metric: plugin_id.to_string(),
                        fingerprint: hex::encode(bundle.publisher_fingerprint),
                    })
                }
                Err(e) => return Err(load_err(e.to_string())),
            }
        };
        let signer = hex::encode(entry.fingerprint);
        if !signer.eq_ignore_ascii_case(&plugin_id.publisher) {
            return Err(load_err(format!(
                "signed by {signer}, but the manifest names publisher {}",
                plugin_id.publisher
            )));
        }

        let reference = MetricRef {
            plugin: plugin_id.clone(),
            publisher_key: entry.public_key,
            artifact_blake3: *blake3::hash(wasm).as_bytes(),
        };
        if let Some(existing) = self.metrics.read().get(&reference.artifact_blake3) {
            return Ok(existing.reference.clone());
        }

        let engine = self.engine()?;
        let metric = LoadedMetric::from_bytes(
            &engine,
            wasm,
            plugin_id,
            reference.artifact_blake3,
            self.owner.clone(),
        )
        .map_err(|e| load_err(format!("not an entangle:integrity/metric component: {e}")))?;

        self.metrics
            .write()
            .entry(reference.artifact_blake3)
            .or_insert(MetricEntry {
                reference: reference.clone(),
                metric,
            });
        Ok(reference)
    }

    /// §7.5 Rule 2: is `metric`'s publisher key on this node's keyring?
    ///
    /// Checks that the reference is self-consistent (its key hashes to the
    /// plugin id's publisher) and that the keyring holds an entry with that
    /// fingerprint **and that exact key**.
    pub fn check_trusted(&self, metric: &MetricRef) -> Result<(), IntegrityError> {
        if !metric.is_self_consistent() {
            return Err(IntegrityError::MetricRefInconsistent {
                metric: metric.plugin.to_string(),
            });
        }
        let fp = metric.publisher_fingerprint();
        let kr = self.keyring.read();
        match kr.lookup(&fp) {
            Some(entry) if entry.public_key == metric.publisher_key => Ok(()),
            _ => Err(IntegrityError::MetricNotInKeyring {
                metric: metric.plugin.to_string(),
                fingerprint: hex::encode(fp),
            }),
        }
    }

    /// Whether a verified component with `metric`'s exact BLAKE3 (and plugin
    /// id and key) is loaded.
    pub fn contains(&self, metric: &MetricRef) -> bool {
        self.metrics
            .read()
            .get(&metric.artifact_blake3)
            .is_some_and(|e| e.reference == *metric)
    }

    /// The loaded reference whose plugin id is `id`, if exactly one is loaded.
    ///
    /// Two loaded artifacts under one id (a rebuild) make the lookup
    /// ambiguous, so it returns `None` rather than guessing.
    pub fn find_by_plugin(&self, id: &PluginId) -> Option<MetricRef> {
        let metrics = self.metrics.read();
        let mut hits = metrics.values().filter(|e| e.reference.plugin == *id);
        let first = hits.next()?;
        if hits.next().is_some() {
            return None;
        }
        Some(first.reference.clone())
    }

    /// Every loaded reference, sorted by plugin id then artifact.
    pub fn list(&self) -> Vec<MetricRef> {
        let mut v: Vec<MetricRef> = self
            .metrics
            .read()
            .values()
            .map(|e| e.reference.clone())
            .collect();
        v.sort_by(|a, b| {
            (a.plugin.to_string(), a.artifact_blake3)
                .cmp(&(b.plugin.to_string(), b.artifact_blake3))
        });
        v
    }

    /// Run `metric.compare(a, b)` once — one component instantiation.
    ///
    /// Re-checks keyring trust first, so a publisher key removed after the
    /// metric was loaded stops the metric from being used. A result that is
    /// `NaN` or negative is [`IntegrityError::MetricContractViolation`];
    /// `+inf` is a valid "incomparable".
    pub async fn compare(
        &self,
        metric: &MetricRef,
        a: &[u8],
        b: &[u8],
    ) -> Result<f64, IntegrityError> {
        self.check_trusted(metric)?;
        let loaded = self
            .metrics
            .read()
            .get(&metric.artifact_blake3)
            .filter(|e| e.reference == *metric)
            .map(|e| e.metric.clone())
            .ok_or_else(|| IntegrityError::MetricUnavailable {
                metric: metric.plugin.to_string(),
                artifact: metric.artifact_hex(),
            })?;
        let engine = self.engine()?;
        let distance = loaded
            .compare(&engine, a, b, self.timeout_ms, self.limits)
            .await
            .map_err(|e| IntegrityError::MetricFailed {
                metric: metric.plugin.to_string(),
                reason: e.to_string(),
            })?;
        if distance.is_nan() || distance < 0.0 {
            return Err(IntegrityError::MetricContractViolation {
                metric: metric.plugin.to_string(),
                distance,
            });
        }
        Ok(distance)
    }

    /// How many times the component `metric` names has been instantiated on
    /// this node (0 if it is not loaded).
    pub fn instantiations(&self, metric: &MetricRef) -> u64 {
        self.metrics
            .read()
            .get(&metric.artifact_blake3)
            .map_or(0, |e| e.metric.instantiations())
    }

    /// Instantiations across every loaded metric on this node.
    pub fn total_instantiations(&self) -> u64 {
        self.metrics
            .read()
            .values()
            .map(|e| e.metric.instantiations())
            .sum()
    }

    fn engine(&self) -> Result<HostEngine, IntegrityError> {
        let mut slot = self.engine.lock();
        if let Some(engine) = slot.as_ref() {
            return Ok(engine.clone());
        }
        let engine = HostEngine::new().map_err(|e| IntegrityError::MetricLoad {
            source_path: "<engine>".into(),
            reason: format!("creating the metric engine: {e}"),
        })?;
        *slot = Some(engine.clone());
        Ok(engine)
    }
}
