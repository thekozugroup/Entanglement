//! The [`Kernel`] — top-level orchestrator that wires together all subsystems.

use crate::{
    errors::RuntimeError,
    lifecycle::{LifecycleEvent, LifecyclePhase},
    loader::PluginPackage,
};
use entangle_broker::{Broker, BrokerPolicy};
use entangle_host::{HostEngine, LoadedPlugin};
use entangle_ipc::{Bus, Envelope, Topic};
use entangle_manifest::loader::load_manifest;
use entangle_signing::{verify_artifact, Keyring, SignatureBundle};
use entangle_types::{plugin_id::PluginId, tier::Tier};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

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

struct LoadedRecord {
    effective_tier: Tier,
    plugin: LoadedPlugin,
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
    engine: HostEngine,
    broker: Broker,
    keyring: Arc<RwLock<Keyring>>,
    plugins: RwLock<HashMap<PluginId, LoadedRecord>>,
    bus: Bus<LifecycleEvent>,
}

impl Kernel {
    /// Construct a new kernel with the given config and trusted keyring.
    pub fn new(config: KernelConfig, keyring: Keyring) -> Result<Self, RuntimeError> {
        let policy = BrokerPolicy {
            max_tier_allowed: config.max_tier_allowed,
            multi_node: config.multi_node,
            peer_allowlist_populated: false,
        };
        let engine = HostEngine::new().map_err(entangle_host::HostError::LinkerSetup)?;
        Ok(Self {
            bus: Bus::new(config.bus_capacity),
            broker: Broker::new(policy),
            engine,
            keyring: Arc::new(RwLock::new(keyring)),
            plugins: RwLock::new(HashMap::new()),
            config,
        })
    }

    /// Access the capability broker.
    pub fn broker(&self) -> &Broker {
        &self.broker
    }

    /// Access the lifecycle IPC bus.
    pub fn bus(&self) -> &Bus<LifecycleEvent> {
        &self.bus
    }

    /// Clone the keyring handle.
    pub fn keyring(&self) -> Arc<RwLock<Keyring>> {
        self.keyring.clone()
    }

    /// Run the full five-step plugin load pipeline (spec §3).
    ///
    /// Steps:
    /// 1. Load and validate the manifest (`entangle.toml`).
    /// 2. Verify the artifact signature against the trusted keyring.
    /// 3. Register the plugin with the capability broker.
    /// 4. Compile the artifact with the host engine.
    /// 5. Emit lifecycle events on the IPC bus after each step.
    ///
    /// Returns the [`PluginId`] on success, or the first error encountered.
    pub async fn load_plugin_from_dir(&self, dir: &Path) -> Result<PluginId, RuntimeError> {
        let pkg = PluginPackage::from_directory(dir)?;

        // ── Step 1: Manifest ─────────────────────────────────────────────────
        let manifest = load_manifest(&pkg.manifest_path)?;
        let plugin_id = manifest.plugin_id.clone();
        let effective_tier = manifest.effective_tier;

        self.emit(
            plugin_id.clone(),
            effective_tier,
            LifecyclePhase::ManifestValidated,
        );

        // ── Step 2: Signature ────────────────────────────────────────────────
        let sig_bytes = std::fs::read(&pkg.signature_path)?;
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

        {
            let kr = self.keyring.read();
            verify_artifact(&pkg.bytes, &bundle, &kr)?;
        }
        self.emit(
            plugin_id.clone(),
            effective_tier,
            LifecyclePhase::SignatureVerified,
        );

        // ── Step 3: Broker ───────────────────────────────────────────────────
        // register_plugin takes ownership of ValidatedManifest (not Clone).
        self.broker.register_plugin(manifest)?;
        self.emit(
            plugin_id.clone(),
            effective_tier,
            LifecyclePhase::Registered,
        );

        // ── Step 4: Host ─────────────────────────────────────────────────────
        let plugin =
            LoadedPlugin::from_bytes(&self.engine, &pkg.bytes, plugin_id.clone(), effective_tier)?;
        self.emit(plugin_id.clone(), effective_tier, LifecyclePhase::Loaded);

        // ── Bookkeeping ───────────────────────────────────────────────────────
        let prev = self.plugins.write().insert(
            plugin_id.clone(),
            LoadedRecord {
                effective_tier,
                plugin,
            },
        );
        if prev.is_some() {
            return Err(RuntimeError::AlreadyLoaded(plugin_id));
        }

        Ok(plugin_id)
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
        let (plugin, effective_tier) = {
            let plugins = self.plugins.read();
            let record = plugins
                .get(plugin_id)
                .ok_or_else(|| RuntimeError::NotLoaded(plugin_id.clone()))?;
            (record.plugin.clone(), record.effective_tier)
        };

        self.emit(plugin_id.clone(), effective_tier, LifecyclePhase::Activated);
        let result = plugin.run_one_shot(&self.engine, input, timeout_ms).await;
        self.emit(plugin_id.clone(), effective_tier, LifecyclePhase::Idled);

        Ok(result?.output)
    }

    /// Invoke a [`OneShotTask`] honoring its [`IntegrityPolicy`] (spec §7.5).
    ///
    /// Phase 1 enforcement:
    /// - [`IntegrityPolicy::None`] — delegates straight to [`Kernel::invoke`].
    /// - [`IntegrityPolicy::TrustedExecutor`] — checks that `local_peer` appears in
    ///   the allowlist; then delegates to [`Kernel::invoke`].
    /// - [`IntegrityPolicy::Deterministic { replicas: N }`] — when `N >= 2`, runs the
    ///   plugin locally `N` times and BLAKE3-compares all outputs. Returns the
    ///   canonical (first) output on agreement, [`RuntimeError::Integrity`] on mismatch.
    ///   `N == 0` or `N == 1` are treated as no-ops (single invocation).
    /// - [`IntegrityPolicy::SemanticEquivalent`] / [`IntegrityPolicy::Attested`] —
    ///   immediately returns [`IntegrityError::NotImplemented`] (Phase 2/3).
    ///
    /// [`IntegrityPolicy`]: entangle_types::task::IntegrityPolicy
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
        let record = self
            .plugins
            .write()
            .remove(plugin)
            .ok_or_else(|| RuntimeError::NotLoaded(plugin.clone()))?;
        self.broker.unregister_plugin(plugin)?;
        self.emit(
            plugin.clone(),
            record.effective_tier,
            LifecyclePhase::Unloaded,
        );
        Ok(())
    }

    /// Return the ids of all currently loaded plugins.
    pub fn list_plugins(&self) -> Vec<PluginId> {
        self.plugins.read().keys().cloned().collect()
    }

    // ── private ──────────────────────────────────────────────────────────────

    fn emit(&self, plugin: PluginId, effective_tier: Tier, phase: LifecyclePhase) {
        let evt = LifecycleEvent {
            plugin,
            phase,
            effective_tier,
            at: SystemTime::now(),
        };
        let topic = Topic::new("runtime.plugin.lifecycle").expect("static topic is valid");
        let env = Envelope::new(topic, evt);
        // Ignore "no subscribers" — lifecycle events are best-effort when no
        // consumer has subscribed yet.
        let _ = self.bus.publish(env);
    }
}
