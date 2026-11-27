//! The [`Kernel`] — top-level orchestrator that wires together all subsystems.

use crate::{
    errors::RuntimeError,
    lifecycle::{LifecycleEvent, LifecyclePhase},
    loader::PluginPackage,
};
use entangle_broker::{Broker, BrokerPolicy};
use entangle_host::{HostEngine, LoadedPlugin};
use entangle_ipc::{Bus, Envelope, Topic};
use entangle_manifest::{loader::LoadError, validate::validate, ValidatedManifest};
use entangle_signing::{verify_artifact, Keyring, SignatureBundle};
use entangle_types::{plugin_id::PluginId, tier::Tier};
use parking_lot::RwLock;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

mod tier_change;

// One absolute deadline covers every registry/guest reservation in an operator request.
const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

async fn wait_for_drain<F: std::future::Future>(
    deadline: tokio::time::Instant,
    wait: F,
) -> Result<F::Output, RuntimeError> {
    tokio::time::timeout_at(deadline, wait)
        .await
        .map_err(|_| RuntimeError::DrainTimeout(DRAIN_TIMEOUT))
}
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
pub use tier_change::TierChange;

/// The topic every [`LifecycleEvent`] is published on.
const LIFECYCLE_TOPIC: &str = "runtime.plugin.lifecycle";

/// Daemon-wide configuration for the [`Kernel`].
#[derive(Clone, Debug)]
pub struct KernelConfig {
    /// Maximum tier plugins are allowed to declare. Plugins above this are
    /// refused at broker registration (spec §9.4.1).
    pub max_tier_allowed: Tier,
    /// Whether multi-node mesh mode is active (spec §11 #16).
    pub multi_node: bool,
    /// Capacity of the lifecycle event bus (number of buffered envelopes).
    pub bus_capacity: usize,
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            max_tier_allowed: Tier::Native,
            multi_node: false,
            bus_capacity: 1024,
        }
    }
}

// ── internal per-plugin record ───────────────────────────────────────────────

#[derive(Clone)]
enum LoadedArtifact {
    Compute(LoadedPlugin),
    Metric(crate::VerifiedMetric),
    Stream(entangle_host::stream::StreamingComponent),
}

struct LoadedRecord {
    invocation_gate: Arc<tokio::sync::RwLock<bool>>,
    effective_tier: Tier,
    plugin: LoadedArtifact,
}

// ── Kernel ───────────────────────────────────────────────────────────────────

/// Top-level runtime kernel.
///
/// Owns the host engine, capability broker, trusted keyring, and the lifecycle
/// IPC bus. Call [`Kernel::load_plugin_from_dir`] to run the full five-step
/// load pipeline (spec §3).
pub struct Kernel {
    #[allow(dead_code)] // retained for future daemon config queries
    config: KernelConfig,
    metrics: entangle_observability::Registry,
    engine: HostEngine,
    broker: Broker,
    keyring: Arc<RwLock<Keyring>>,
    keyring_path: Option<PathBuf>,
    plugins: RwLock<HashMap<PluginId, LoadedRecord>>,
    lifecycle_gate: tokio::sync::RwLock<()>,
    generation: AtomicU64,
    disabled: RwLock<BTreeSet<String>>,
    bus: Bus<LifecycleEvent>,
    /// The single topic every lifecycle event is published on. Built once so
    /// `emit` does not re-parse and re-validate the same literal each time.
    lifecycle_topic: Topic,
}

impl Kernel {
    /// Construct a new kernel with the given config and trusted keyring.
    pub fn new(config: KernelConfig, keyring: Keyring) -> Result<Self, RuntimeError> {
        if config.bus_capacity == 0 || config.bus_capacity > usize::MAX / 2 {
            return Err(RuntimeError::InvalidBusCapacity(config.bus_capacity));
        }
        let policy = BrokerPolicy {
            max_tier_allowed: config.max_tier_allowed,
            multi_node: config.multi_node,
            peer_allowlist_populated: false,
        };
        let engine = HostEngine::new().map_err(entangle_host::HostError::LinkerSetup)?;
        Ok(Self {
            bus: Bus::new(config.bus_capacity),
            lifecycle_topic: Topic::new(LIFECYCLE_TOPIC).expect("static topic is valid"),
            broker: Broker::new(policy),
            metrics: entangle_observability::Registry::new(),
            engine,
            keyring: Arc::new(RwLock::new(keyring)),
            keyring_path: None,
            plugins: RwLock::new(HashMap::new()),
            lifecycle_gate: tokio::sync::RwLock::new(()),
            generation: AtomicU64::new(0),
            disabled: RwLock::new(BTreeSet::new()),
            config,
        })
    }

    /// Construct a kernel that verifies each new package against the current
    /// publisher keyring at `path`. Removing the file leaves no trusted publishers.
    pub fn from_keyring_file(config: KernelConfig, path: PathBuf) -> Result<Self, RuntimeError> {
        let mut kernel = Self::new(config, Keyring::load(&path)?)?;
        kernel.keyring_path = Some(path);
        Ok(kernel)
    }

    /// Operator metrics for work performed during this kernel's lifetime.
    pub fn metrics(&self) -> &entangle_observability::Registry {
        &self.metrics
    }

    /// Current number of loaded components.
    pub fn loaded_plugin_count(&self) -> usize {
        self.plugins.read().len()
    }

    /// Access the capability broker.
    pub fn broker(&self) -> &Broker {
        &self.broker
    }

    /// Hold the current tier-5 admission policy stable for a bounded native service call.
    /// Dropping the guard (including on cancellation) lets a pending ceiling change proceed.
    pub async fn native_service_lease(
        &self,
    ) -> Result<tokio::sync::RwLockReadGuard<'_, ()>, RuntimeError> {
        let lease = self.lifecycle_gate.read().await;
        self.broker
            .policy()
            .check_plugin_load(entangle_types::tier::Tier::Native)
            .map_err(entangle_broker::BrokerError::from)?;
        Ok(lease)
    }

    /// Access the lifecycle IPC bus.
    pub fn bus(&self) -> &Bus<LifecycleEvent> {
        &self.bus
    }

    /// Clone the in-memory keyring supplied to [`Kernel::new`].
    /// File-backed kernels use the on-disk keyring for load verification.
    pub fn keyring(&self) -> Arc<RwLock<Keyring>> {
        self.keyring.clone()
    }

    /// Run the full five-step plugin load pipeline (spec §3).
    ///
    /// Steps:
    /// 1. Parse and validate the manifest (`entangle.toml`) from the exact
    ///    bytes covered by the signature, and refuse duplicate plugin ids
    ///    up front.
    /// 2. Verify the signature bundle over the artifact **and** manifest
    ///    bytes against the trusted keyring, then bind the verified signer
    ///    to the publisher named in the manifest.
    /// 3. Register the plugin with the capability broker.
    /// 4. Compile the artifact with the host engine (rolling back the broker
    ///    registration on failure — no partial state remains).
    /// 5. Emit lifecycle events on the IPC bus after each step.
    ///
    /// Returns the [`PluginId`] on success, or the first error encountered.
    ///
    /// The manifest's tier and capability declarations are only trusted after
    /// step 2: the signature covers `BLAKE3(manifest)`, so editing
    /// `entangle.toml` post-signing (e.g. raising the tier) fails verification
    /// with [`entangle_signing::VerificationError::ManifestHashMismatch`].
    pub async fn load_plugin_from_dir(&self, dir: &Path) -> Result<PluginId, RuntimeError> {
        let _admission = self.lifecycle_gate.read().await;
        let pkg = PluginPackage::from_directory(dir)?;

        // ── Step 1: Manifest ─────────────────────────────────────────────────
        // Parse from the in-memory bytes (the same bytes step 2 hashes), not
        // from a second disk read that could observe a different file.
        let manifest = parse_manifest(&pkg.manifest_bytes)?;
        let plugin_id = manifest.plugin_id.clone();
        let effective_tier = manifest.effective_tier;
        if self.disabled.read().contains(&plugin_id.to_string()) {
            return Err(RuntimeError::Disabled(plugin_id));
        }

        // Duplicate check FIRST — before any broker or host state exists, so
        // a rejected re-load leaves the running plugin fully intact.
        if self.plugins.read().contains_key(&plugin_id) {
            return Err(RuntimeError::AlreadyLoaded(plugin_id));
        }

        self.emit(
            &plugin_id,
            effective_tier,
            LifecyclePhase::ManifestValidated,
        );

        // ── Step 2: Signature (artifact + manifest) ──────────────────────────
        let sig_bytes = pkg.read_signature()?;
        let sig_text = std::str::from_utf8(&sig_bytes).map_err(|_| {
            RuntimeError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "signature bundle is not valid UTF-8",
            ))
        })?;
        let bundle: SignatureBundle = toml::from_str(sig_text).map_err(|e| {
            RuntimeError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("signature bundle TOML parse error: {e}"),
            ))
        })?;

        let verify_publisher = |keys: &Keyring| {
            verify_artifact(&pkg.bytes, &pkg.manifest_bytes, &bundle, keys)
                .map(|entry| (hex::encode(entry.fingerprint), entry.public_key))
        };
        let (signer_fingerprint, publisher) = match &self.keyring_path {
            Some(path) => verify_publisher(&Keyring::load(path)?)?,
            None => verify_publisher(&self.keyring.read())?,
        };

        // ── Step 2b: Publisher binding ───────────────────────────────────────
        // The key that verified must be the publisher the manifest names —
        // otherwise any trusted publisher could sign packages impersonating
        // another publisher's plugin id.
        entangle_signing::artifact::verify_publisher_binding(
            &plugin_id.publisher,
            manifest
                .raw
                .signature
                .as_ref()
                .map(|s| (s.publisher.as_str(), s.algorithm.as_str())),
            &signer_fingerprint,
            &bundle.algorithm,
        )?;
        self.emit(
            &plugin_id,
            effective_tier,
            LifecyclePhase::SignatureVerified,
        );

        // ── Step 3: Broker ───────────────────────────────────────────────────
        // register_plugin takes ownership of ValidatedManifest (not Clone).
        let build_world = manifest
            .raw
            .build
            .as_ref()
            .and_then(|b| b.wit_world.as_deref());
        let metric_world = matches!(
            build_world,
            Some(crate::metric::METRIC_WORLD | "entangle:integrity@0.1.0/comparator")
        );
        let stream_world = matches!(
            build_world,
            Some("entangle:plugin/stream-plugin@0.1.0" | "entangle:plugin@0.1.0/stream-plugin")
        );
        let libtest_world = build_world == Some(entangle_host::LIBTEST_WORLD);
        if metric_world && effective_tier > Tier::Sandboxed {
            return Err(entangle_host::HostError::PluginReturnedError(
                "integrity metrics require tier 1 or 2".into(),
            )
            .into());
        }
        if libtest_world && (effective_tier != Tier::Pure || !manifest.capabilities.is_empty()) {
            return Err(entangle_host::HostError::PluginReturnedError(
                "WASI libtest suites require tier 1 with no capabilities".into(),
            )
            .into());
        }
        if manifest.raw.plugin.runtime == entangle_manifest::Runtime::Native {
            self.broker
                .policy()
                .check_plugin_load(effective_tier)
                .map_err(entangle_broker::BrokerError::from)?;
            return Err(RuntimeError::NativeUnavailable(plugin_id));
        }
        self.broker.register_plugin(manifest)?;
        self.emit(&plugin_id, effective_tier, LifecyclePhase::Registered);

        // ── Step 4: Host ─────────────────────────────────────────────────────
        // On failure, roll back the broker registration so no partial state
        // remains from this load attempt.
        let invocation_gate = Arc::new(tokio::sync::RwLock::new(true));
        let compiled = if metric_world {
            entangle_host::metric::MetricComponent::compile(&self.engine, &pkg.bytes).map(
                |component| {
                    LoadedArtifact::Metric(crate::VerifiedMetric {
                        cid: *blake3::hash(&pkg.bytes).as_bytes(),
                        publisher,
                        id: plugin_id.clone(),
                        component,
                        invocation_gate: Arc::clone(&invocation_gate),
                    })
                },
            )
        } else if stream_world {
            entangle_host::stream::StreamingComponent::compile(
                &self.engine,
                &pkg.bytes,
                plugin_id.clone(),
                effective_tier,
            )
            .map(LoadedArtifact::Stream)
        } else if libtest_world {
            LoadedPlugin::from_libtest(&self.engine, &pkg.bytes, plugin_id.clone())
                .map(LoadedArtifact::Compute)
        } else {
            LoadedPlugin::from_bytes(&self.engine, &pkg.bytes, plugin_id.clone(), effective_tier)
                .map(LoadedArtifact::Compute)
        };
        let plugin = match compiled {
            Ok(p) => p,
            Err(e) => {
                let _ = self.broker.unregister_plugin(&plugin_id);
                return Err(e.into());
            }
        };
        self.emit(&plugin_id, effective_tier, LifecyclePhase::Loaded);

        // ── Bookkeeping ───────────────────────────────────────────────────────
        // A concurrent load of the same id would have failed at broker
        // registration (insert-only), so the slot is expected to be vacant;
        // never overwrite an existing record.
        match self.plugins.write().entry(plugin_id.clone()) {
            std::collections::hash_map::Entry::Occupied(_) => {
                return Err(RuntimeError::AlreadyLoaded(plugin_id));
            }
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(LoadedRecord {
                    invocation_gate,
                    effective_tier,
                    plugin,
                });
            }
        }

        self.generation.fetch_add(1, Ordering::Relaxed);
        Ok(plugin_id)
    }

    /// Look up a locally loaded integrity metric and recheck current publisher trust.
    /// Compilation and lookup do not create a guest instance.
    pub fn prepare_metric(&self, id: &PluginId) -> Result<crate::VerifiedMetric, RuntimeError> {
        let metric = match self.plugins.read().get(id).map(|r| &r.plugin) {
            Some(LoadedArtifact::Metric(metric)) => metric.clone(),
            _ => return Err(RuntimeError::MetricNotInKeyring(id.clone())),
        };
        let fingerprint: [u8; 16] = blake3::hash(&metric.publisher).as_bytes()[..16]
            .try_into()
            .expect("16-byte fingerprint");
        let trusted = |keys: &Keyring| {
            keys.lookup(&fingerprint)
                .is_some_and(|entry| entry.public_key == metric.publisher)
        };
        let valid = match &self.keyring_path {
            Some(path) => trusted(&Keyring::load(path)?),
            None => trusted(&self.keyring.read()),
        };
        if !valid {
            return Err(RuntimeError::MetricNotInKeyring(id.clone()));
        }
        Ok(metric)
    }

    /// Whether this loaded package implements the progressive streaming world.
    pub fn is_stream_plugin(&self, id: &PluginId) -> bool {
        self.plugins
            .read()
            .get(id)
            .is_some_and(|record| matches!(record.plugin, LoadedArtifact::Stream(_)))
    }

    /// Execute the signed streaming guest with one acknowledged write per guest yield.
    pub async fn invoke_stream<F, Fut>(
        &self,
        id: &PluginId,
        input: &[u8],
        timeout_ms: u64,
        max_chunk_bytes: u32,
        max_total_bytes: u64,
        emit: F,
    ) -> Result<(), RuntimeError>
    where
        F: Fn(Vec<u8>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<(), String>> + Send + 'static,
    {
        let (stream, tier, _guard) = {
            let plugins = self.plugins.read();
            let record = plugins
                .get(id)
                .ok_or_else(|| RuntimeError::NotLoaded(id.clone()))?;
            let guard = record
                .invocation_gate
                .clone()
                .try_read_owned()
                .map_err(|_| RuntimeError::Draining(id.clone()))?;
            if !*guard {
                return Err(RuntimeError::NotLoaded(id.clone()));
            }
            let LoadedArtifact::Stream(stream) = &record.plugin else {
                return Err(RuntimeError::NotStreamPlugin(id.clone()));
            };
            (stream.clone(), record.effective_tier, guard)
        };
        self.emit(id, tier, LifecyclePhase::Activated);
        let limits = entangle_host::stream::StreamLimits {
            timeout_ms,
            max_chunk_bytes,
            max_total_bytes,
        };
        let result = stream.run(&self.engine, input, limits, emit).await;
        self.emit(id, tier, LifecyclePhase::Idled);
        result.map_err(|error| match error {
            entangle_host::HostError::StreamTotalBytesExceeded { limit, actual } => {
                RuntimeError::StreamTotalBytesExceeded { limit, actual }
            }
            entangle_host::HostError::StreamChunkSizeExceeded { limit, actual } => {
                RuntimeError::StreamChunkSizeExceeded { limit, actual }
            }
            other => other.into(),
        })
    }

    /// Invoke a loaded plugin's `run` export with `input` bytes; returns the
    /// plugin's output bytes.
    ///
    /// Emits [`LifecyclePhase::Activated`] before calling into the plugin and
    /// [`LifecyclePhase::Idled`] after it returns (whether or not it errors).
    pub async fn invoke(
        &self,
        plugin_id: &PluginId,
        input: &[u8],
        timeout_ms: u64,
    ) -> Result<Vec<u8>, RuntimeError> {
        // Acquire the read lock, clone what we need, then release it before
        // the async call so we don't hold a lock across an .await point.
        let (plugin, effective_tier, _active) = {
            let plugins = self.plugins.read();
            let record = plugins
                .get(plugin_id)
                .ok_or_else(|| RuntimeError::NotLoaded(plugin_id.clone()))?;
            let guard = record
                .invocation_gate
                .clone()
                .try_read_owned()
                .map_err(|_| RuntimeError::Draining(plugin_id.clone()))?;
            if !*guard {
                return Err(RuntimeError::NotLoaded(plugin_id.clone()));
            }
            (record.plugin.clone(), record.effective_tier, guard)
        };

        let LoadedArtifact::Compute(plugin) = plugin else {
            return Err(RuntimeError::NotComputePlugin(plugin_id.clone()));
        };
        self.emit(plugin_id, effective_tier, LifecyclePhase::Activated);
        let started = std::time::Instant::now();
        let result = plugin.run_one_shot(&self.engine, input, timeout_ms).await;
        self.metrics.observe_histogram(
            "entangle_wasm_invocation_seconds",
            "Time spent running loaded WASI components on this worker",
            &[("result", if result.is_ok() { "ok" } else { "error" })],
            &[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 30.0, 300.0],
            started.elapsed().as_secs_f64(),
        );
        self.emit(plugin_id, effective_tier, LifecyclePhase::Idled);

        Ok(result?.output)
    }

    /// Invoke a [`entangle_types::task::OneShotTask`] honoring its
    /// [`entangle_types::task::IntegrityPolicy`] (spec §7.5).
    ///
    /// Phase 1 enforcement:
    /// - `IntegrityPolicy::None` — delegates straight to [`Kernel::invoke`].
    /// - `IntegrityPolicy::TrustedExecutor` — checks that `local_peer` appears in
    ///   the allowlist; then delegates to [`Kernel::invoke`].
    /// - `IntegrityPolicy::Deterministic { replicas: N }` — when `N >= 2`, runs the
    ///   plugin locally `N` times and BLAKE3-compares all outputs. Returns the
    ///   canonical (first) output on agreement, [`RuntimeError::Integrity`] on mismatch.
    ///   `N == 0` or `N == 1` are treated as no-ops (single invocation).
    /// - `IntegrityPolicy::SemanticEquivalent` / `IntegrityPolicy::Attested` —
    ///   immediately returns [`IntegrityError::NotImplemented`] (Phase 2/3).
    ///
    /// [`IntegrityError::NotImplemented`]: crate::integrity::IntegrityError::NotImplemented
    pub async fn invoke_with_integrity(
        &self,
        task: &entangle_types::task::OneShotTask,
        local_peer: entangle_types::peer_id::PeerId,
    ) -> Result<Vec<u8>, RuntimeError> {
        use crate::integrity::{
            check_trusted_executor, verify_deterministic, IntegrityError, ReplicaOutput,
        };
        use entangle_types::task::IntegrityPolicy;

        match &task.integrity {
            IntegrityPolicy::None => {
                self.invoke(&task.plugin, &task.input, task.timeout_ms)
                    .await
            }
            IntegrityPolicy::TrustedExecutor { .. } => {
                check_trusted_executor(&task.integrity, &local_peer)?;
                self.invoke(&task.plugin, &task.input, task.timeout_ms)
                    .await
            }
            IntegrityPolicy::Deterministic { replicas } => {
                if *replicas == 0 || *replicas == 1 {
                    // N=0 and N=1 are no-ops: fall through to a single invoke.
                    return self
                        .invoke(&task.plugin, &task.input, task.timeout_ms)
                        .await;
                }
                let mut outs: Vec<ReplicaOutput> = Vec::with_capacity(*replicas as usize);
                for _ in 0..*replicas {
                    let bytes = self
                        .invoke(&task.plugin, &task.input, task.timeout_ms)
                        .await?;
                    let h = blake3::hash(&bytes);
                    outs.push(ReplicaOutput {
                        blake3: *h.as_bytes(),
                        bytes,
                    });
                }
                let chosen = verify_deterministic(&outs, *replicas)?;
                Ok(chosen.bytes.clone())
            }
            IntegrityPolicy::SemanticEquivalent { .. } => Err(RuntimeError::Integrity(
                IntegrityError::NotImplemented("SemanticEquivalent"),
            )),
            IntegrityPolicy::Attested { .. } => Err(RuntimeError::Integrity(
                IntegrityError::NotImplemented("Attested"),
            )),
        }
    }

    /// Unload a currently-loaded plugin.
    ///
    /// De-registers from the broker and emits a [`LifecyclePhase::Unloaded`] event.
    pub async fn unload(&self, plugin: &PluginId) -> Result<(), RuntimeError> {
        let deadline = tokio::time::Instant::now() + DRAIN_TIMEOUT;
        let _registry = wait_for_drain(deadline, self.lifecycle_gate.write()).await?;
        let gate = self
            .plugins
            .read()
            .get(plugin)
            .map(|record| record.invocation_gate.clone())
            .ok_or_else(|| RuntimeError::NotLoaded(plugin.clone()))?;
        let mut active = wait_for_drain(deadline, gate.write()).await?;
        *active = false;
        let record = self
            .plugins
            .write()
            .remove(plugin)
            .expect("reserved plugin");
        self.release_record(plugin, record);
        Ok(())
    }

    fn release_record(&self, plugin: &PluginId, record: LoadedRecord) {
        self.broker.remove_plugin(plugin);
        self.emit(plugin, record.effective_tier, LifecyclePhase::Unloaded);
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    /// Whether this kernel currently has the requested plugin loaded.
    pub fn has_plugin(&self, plugin: &PluginId) -> bool {
        self.plugins.read().contains_key(plugin)
    }

    /// True when an ordinary one-shot invocation can call the loaded artifact.
    pub fn has_compute_plugin(&self, plugin: &PluginId) -> bool {
        self.plugins
            .read()
            .get(plugin)
            .is_some_and(|r| matches!(r.plugin, LoadedArtifact::Compute(_)))
    }

    /// Snapshot the one-shot (including libtest) and progressive-only guest IDs.
    /// Integrity comparators have no worker invocation entry point.
    pub fn execution_plugins(&self) -> (HashSet<PluginId>, HashSet<PluginId>) {
        let mut compute = HashSet::new();
        let mut progressive = HashSet::new();
        for (id, record) in self.plugins.read().iter() {
            match &record.plugin {
                LoadedArtifact::Compute(_) => {
                    compute.insert(id.clone());
                }
                LoadedArtifact::Stream(_) => {
                    progressive.insert(id.clone());
                }
                LoadedArtifact::Metric(_) => {}
            }
        }
        (compute, progressive)
    }

    /// Return the ids of all currently loaded plugins, sorted by their
    /// string form.
    ///
    /// Deterministic ordering matters for `entangle plugins list --json`
    /// (avoid spurious diffs in operator scripts) and for the daemon's
    /// audit-log replay.
    pub fn list_plugins(&self) -> Vec<PluginId> {
        let mut v: Vec<PluginId> = self.plugins.read().keys().cloned().collect();
        v.sort_by_key(|a| a.to_string());
        v
    }

    // ── private ──────────────────────────────────────────────────────────────

    fn emit(&self, plugin: &PluginId, effective_tier: Tier, phase: LifecyclePhase) {
        // Lifecycle events are best-effort: with nobody subscribed, `publish`
        // can only fail with `NoSubscribers` and drop the envelope — after
        // having cloned the `PluginId`, read the clock and minted a UUID.
        // `invoke` emits twice per call, so that is pure waste on the hottest
        // path in the kernel. Checking first is safe precisely because the
        // event is best-effort *and* because a subscriber that attaches after
        // this check would not have received the envelope anyway:
        // `Bus::subscribe` only yields envelopes published after it returns.
        if self.bus.subscriber_count() == 0 {
            return;
        }
        let evt = LifecycleEvent {
            plugin: plugin.clone(),
            phase,
            effective_tier,
            at: SystemTime::now(),
        };
        // `lifecycle_topic` is built once in `Kernel::new`; re-parsing and
        // re-validating the same static string on every event is not free.
        let env = Envelope::new(self.lifecycle_topic.clone(), evt);
        let _ = self.bus.publish(env);
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Parse and validate an `entangle.toml` manifest from raw bytes.
///
/// The kernel deliberately parses the same in-memory bytes whose hash is
/// checked against the signature bundle, instead of re-reading the file.
fn parse_manifest(bytes: &[u8]) -> Result<ValidatedManifest, RuntimeError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        RuntimeError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "manifest is not valid UTF-8",
        ))
    })?;
    let raw: entangle_manifest::schema::Manifest =
        toml::from_str(text).map_err(|e| RuntimeError::Manifest(LoadError::Parse(e)))?;
    Ok(validate(raw)?)
}
