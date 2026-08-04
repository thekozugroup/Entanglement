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
use entangle_signing::{verify_artifact, Keyring, SignatureBundle, VerificationError};
use entangle_types::{plugin_id::PluginId, tier::Tier};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

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
    /// The single topic every lifecycle event is published on. Built once so
    /// `emit` does not re-parse and re-validate the same literal each time.
    lifecycle_topic: Topic,
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
            lifecycle_topic: Topic::new(LIFECYCLE_TOPIC).expect("static topic is valid"),
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
    /// with [`VerificationError::ManifestHashMismatch`].
    pub async fn load_plugin_from_dir(&self, dir: &Path) -> Result<PluginId, RuntimeError> {
        let pkg = PluginPackage::from_directory(dir)?;

        // ── Step 1: Manifest ─────────────────────────────────────────────────
        // Parse from the in-memory bytes (the same bytes step 2 hashes), not
        // from a second disk read that could observe a different file.
        let manifest = parse_manifest(&pkg.manifest_bytes)?;
        let plugin_id = manifest.plugin_id.clone();
        let effective_tier = manifest.effective_tier;

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

        let signer_fingerprint = {
            let kr = self.keyring.read();
            let entry = verify_artifact(&pkg.bytes, &pkg.manifest_bytes, &bundle, &kr)?;
            hex::encode(entry.fingerprint)
        };

        // ── Step 2b: Publisher binding ───────────────────────────────────────
        // The key that verified must be the publisher the manifest names —
        // otherwise any trusted publisher could sign packages impersonating
        // another publisher's plugin id.
        if !signer_fingerprint.eq_ignore_ascii_case(&plugin_id.publisher) {
            return Err(RuntimeError::Signing(
                VerificationError::PublisherMismatch {
                    manifest_publisher: plugin_id.publisher.clone(),
                    signer_fingerprint,
                },
            ));
        }
        // Optional `[signature]` manifest section: when present it must agree
        // with the bundle that actually verified (narrowing only).
        if let Some(section) = &manifest.raw.signature {
            if !section.publisher.eq_ignore_ascii_case(&signer_fingerprint) {
                return Err(RuntimeError::Signing(
                    VerificationError::PublisherMismatch {
                        manifest_publisher: section.publisher.clone(),
                        signer_fingerprint,
                    },
                ));
            }
            if section.algorithm != bundle.algorithm {
                return Err(RuntimeError::Signing(
                    VerificationError::UnsupportedAlgorithm(section.algorithm.clone()),
                ));
            }
        }
        self.emit(
            &plugin_id,
            effective_tier,
            LifecyclePhase::SignatureVerified,
        );

        // ── Step 3: Broker ───────────────────────────────────────────────────
        // register_plugin takes ownership of ValidatedManifest (not Clone).
        self.broker.register_plugin(manifest)?;
        self.emit(&plugin_id, effective_tier, LifecyclePhase::Registered);

        // ── Step 4: Host ─────────────────────────────────────────────────────
        // On failure, roll back the broker registration so no partial state
        // remains from this load attempt.
        let plugin = match LoadedPlugin::from_bytes(
            &self.engine,
            &pkg.bytes,
            plugin_id.clone(),
            effective_tier,
        ) {
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
                    effective_tier,
                    plugin,
                });
            }
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

        self.emit(plugin_id, effective_tier, LifecyclePhase::Activated);
        let result = plugin.run_one_shot(&self.engine, input, timeout_ms).await;
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
        let record = self
            .plugins
            .write()
            .remove(plugin)
            .ok_or_else(|| RuntimeError::NotLoaded(plugin.clone()))?;
        self.broker.unregister_plugin(plugin)?;
        self.emit(plugin, record.effective_tier, LifecyclePhase::Unloaded);
        Ok(())
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
