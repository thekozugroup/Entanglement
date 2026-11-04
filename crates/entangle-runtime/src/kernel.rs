//! The [`Kernel`] — top-level orchestrator that wires together all subsystems.

use crate::{
    errors::RuntimeError,
    lifecycle::{LifecycleEvent, LifecyclePhase},
    loader::PluginPackage,
    native::{NativeConfig, NativePlugin},
};
use entangle_broker::{Broker, BrokerError, BrokerPolicy};
use entangle_host::{check_runtime_kind, DeclaredRuntime, HostEngine, LoadedPlugin};
use entangle_ipc::{Bus, Envelope, Topic};
use entangle_manifest::Runtime;
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
    /// Native (tier 4–5) plugin settings: sandbox opt-out, storage root,
    /// limits (spec §3.4).
    pub native: NativeConfig,
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            max_tier_allowed: Tier::Native,
            multi_node: false,
            bus_capacity: 1024,
            native: NativeConfig::default(),
        }
    }
}

// ── internal per-plugin record ───────────────────────────────────────────────

struct LoadedRecord {
    effective_tier: Tier,
    plugin: PluginImpl,
    loaded_at: std::time::Instant,
}

/// A loaded plugin as reported by the lowering workflow ([`Kernel::plugins_above`]).
#[derive(Clone, Debug)]
pub struct LoadedPluginInfo {
    /// The plugin.
    pub plugin: PluginId,
    /// Its effective tier.
    pub tier: Tier,
    /// True for a native subprocess, false for a Wasm component.
    pub native: bool,
    /// Time since it was loaded.
    pub uptime: std::time::Duration,
}

/// Result of [`Kernel::apply_max_tier`].
#[derive(Clone, Debug)]
pub struct MaxTierOutcome {
    /// Ceiling before the call.
    pub old: Tier,
    /// Ceiling now in force.
    pub new: Tier,
    /// Plugins that were unloaded to honour it.
    pub unloaded: Vec<PluginId>,
}

/// How a loaded plugin executes.
#[derive(Clone)]
enum PluginImpl {
    /// Wasm component in the shared Wasmtime engine.
    Wasm(LoadedPlugin),
    /// Native executable in a sandboxed subprocess (see [`crate::native`]).
    Native(Arc<NativePlugin>),
}

// ── Kernel ───────────────────────────────────────────────────────────────────

/// Top-level runtime kernel.
///
/// Owns the host engine, capability broker, trusted keyring, and the lifecycle
/// IPC bus. Call [`Kernel::load_plugin_from_dir`] to run the full five-step
/// load pipeline (spec §3).
pub struct Kernel {
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
        // Staged native binaries left behind by a process that died without
        // unloading (SIGKILL, OOM kill) would otherwise accumulate across
        // restarts. Only copies no live process holds are removed, so a
        // running daemon sharing this root keeps its own. The system temp
        // dir (no root configured) is left to the OS's tmp cleaning.
        if let Some(root) = &config.native.staging_dir {
            crate::native::sweep_stale_staging(root);
        }
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
    ///    bytes covered by the signature, refuse a tier above
    ///    `max_tier_allowed` (ATC-MAN-4) and duplicate plugin ids up front.
    /// 2. Verify the signature bundle over the artifact **and** manifest
    ///    bytes against the trusted keyring, then bind the verified signer
    ///    to the publisher named in the manifest. Check the artifact's magic
    ///    bytes against the declared runtime (ATC-MAN-3).
    /// 3. Register the plugin with the capability broker.
    /// 4. Wasm: compile the artifact with the host engine. Native: grant the
    ///    declared capabilities through the broker, plan the OS sandbox
    ///    (refusing when none is available), and stage the verified bytes
    ///    (see [`crate::native`]). On failure the broker registration — and
    ///    with it every grant — is rolled back; no partial state remains.
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

        // Tier ceiling FIRST (spec §9.4.1, ATC-MAN-4): a plugin above
        // `max_tier_allowed` is refused before any signature work, broker
        // registration, capability grant, or file write. Refusing on an
        // as-yet-unverified manifest is safe — refusal never grants anything —
        // and the broker re-checks the verified manifest at registration.
        self.broker
            .policy()
            .check_plugin_load(effective_tier)
            .map_err(BrokerError::from)?;

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

        // ── Step 2c: Runtime kind (ATC-MAN-3) ────────────────────────────────
        // The verified bytes must be what the manifest says they are.
        let runtime = manifest.runtime;
        let declared = match runtime {
            Runtime::Wasm => DeclaredRuntime::Wasm,
            Runtime::Native => DeclaredRuntime::Native,
        };
        check_runtime_kind(declared, &pkg.bytes)?;
        let declared_caps = manifest.capabilities.clone();

        // ── Step 3: Broker ───────────────────────────────────────────────────
        // register_plugin takes ownership of ValidatedManifest (not Clone).
        self.broker.register_plugin(manifest)?;
        self.emit(&plugin_id, effective_tier, LifecyclePhase::Registered);

        // ── Step 4: Host / native sandbox ────────────────────────────────────
        // On failure, roll back the broker registration (which also releases
        // any grants, audited) so no partial state remains.
        let plugin = match runtime {
            Runtime::Wasm => LoadedPlugin::from_bytes(
                &self.engine,
                &pkg.bytes,
                plugin_id.clone(),
                effective_tier,
            )
            .map(PluginImpl::Wasm)
            .map_err(RuntimeError::from),
            Runtime::Native => self
                .prepare_native(&plugin_id, &pkg, &declared_caps)
                .map(|n| PluginImpl::Native(Arc::new(n))),
        };
        let plugin = match plugin {
            Ok(p) => p,
            Err(e) => {
                let _ = self.broker.unregister_plugin(&plugin_id);
                return Err(e);
            }
        };

        // ── Bookkeeping ───────────────────────────────────────────────────────
        // A concurrent load of the same id would have failed at broker
        // registration (insert-only), so the slot is expected to be vacant;
        // never overwrite an existing record.
        //
        // The ceiling is checked again here, under the `plugins` write lock
        // that `apply_max_tier` holds while it lowers the ceiling and computes
        // the delta set: the checks above ran under the ceiling in force at
        // that time, and a lowering in between (while the component compiled
        // or the native binary was staged) neither saw this plugin, which is
        // not in `plugins` yet, nor refused it. Under the lock either the
        // lowering already happened (refused here) or it happens after the
        // insert (it then sees and unloads the plugin).
        {
            let mut plugins = self.plugins.write();
            if let Err(e) = self.broker.policy().check_plugin_load(effective_tier) {
                drop(plugins);
                let _ = self.broker.unregister_plugin(&plugin_id);
                return Err(BrokerError::from(e).into());
            }
            match plugins.entry(plugin_id.clone()) {
                std::collections::hash_map::Entry::Occupied(_) => {
                    return Err(RuntimeError::AlreadyLoaded(plugin_id));
                }
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(LoadedRecord {
                        effective_tier,
                        plugin,
                        loaded_at: std::time::Instant::now(),
                    });
                }
            }
        }
        self.emit(&plugin_id, effective_tier, LifecyclePhase::Loaded);

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
        let result = match plugin {
            PluginImpl::Wasm(p) => p
                .run_one_shot(&self.engine, input, timeout_ms)
                .await
                .map(|r| r.output)
                .map_err(RuntimeError::from),
            PluginImpl::Native(n) => n
                .invoke(input, timeout_ms)
                .await
                .map_err(RuntimeError::from),
        };
        self.emit(plugin_id, effective_tier, LifecyclePhase::Idled);

        result
    }

    /// The sandbox plan a loaded native plugin runs under (`None` for wasm
    /// plugins and unknown ids).
    pub fn native_sandbox(&self, plugin_id: &PluginId) -> Option<entangle_sandbox::Plan> {
        match &self.plugins.read().get(plugin_id)?.plugin {
            PluginImpl::Native(n) => Some(n.plan().clone()),
            PluginImpl::Wasm(_) => None,
        }
    }

    /// Grant every declared capability through the broker (audited), derive
    /// the sandbox from the grants, and stage the verified binary.
    fn prepare_native(
        &self,
        plugin_id: &PluginId,
        pkg: &PluginPackage,
        declared: &[entangle_types::capability::CapabilityKind],
    ) -> Result<NativePlugin, RuntimeError> {
        let grants = declared
            .iter()
            .map(|cap| self.broker.grant(plugin_id, cap))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(NativePlugin::prepare(
            plugin_id,
            &pkg.bytes,
            Some(&pkg.dir),
            &grants,
            &self.config.native,
        )?)
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
    /// - `IntegrityPolicy::SemanticEquivalent` — returns
    ///   [`IntegrityError::VerifierRequired`]: it is verified by the
    ///   submitter's scheduler pipeline (`entangle_scheduler::Dispatcher`),
    ///   which replicates across peers and runs the signed metric.
    /// - `IntegrityPolicy::Attested` — returns [`IntegrityError::NotImplemented`]
    ///   (TEE attestation is unsupported until Phase 4+).
    ///
    /// [`IntegrityError::NotImplemented`]: crate::integrity::IntegrityError::NotImplemented
    /// [`IntegrityError::VerifierRequired`]: crate::integrity::IntegrityError::VerifierRequired
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
                IntegrityError::VerifierRequired("SemanticEquivalent"),
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

    /// The tier ceiling currently in force (may differ from the configured
    /// one after [`Kernel::apply_max_tier`]).
    pub fn max_tier_allowed(&self) -> Tier {
        self.broker.policy().max_tier_allowed
    }

    /// Loaded plugins whose effective tier exceeds `ceiling` — the delta set
    /// of the lowering workflow (spec §9.4.1) — with their tier and whether
    /// they are native subprocesses, sorted by plugin id.
    pub fn plugins_above(&self, ceiling: Tier) -> Vec<LoadedPluginInfo> {
        Self::above(&self.plugins.read(), ceiling)
    }

    fn above(plugins: &HashMap<PluginId, LoadedRecord>, ceiling: Tier) -> Vec<LoadedPluginInfo> {
        let mut v: Vec<LoadedPluginInfo> = plugins
            .iter()
            .filter(|(_, r)| r.effective_tier > ceiling)
            .map(|(id, r)| LoadedPluginInfo {
                plugin: id.clone(),
                tier: r.effective_tier,
                native: matches!(r.plugin, PluginImpl::Native(_)),
                uptime: r.loaded_at.elapsed(),
            })
            .collect();
        v.sort_by_key(|i| i.plugin.to_string());
        v
    }

    /// Apply a new tier ceiling at runtime (spec §9.4.1).
    ///
    /// Raising (or keeping) the ceiling unloads nothing. Lowering it unloads
    /// every plugin above the new ceiling **only if `unload` is true**;
    /// otherwise, when the delta set is non-empty, nothing changes and the
    /// affected plugins are returned in `Err` so the caller can prompt. The
    /// unload goes through [`Kernel::unload`], which releases the broker
    /// grants, and one `ENTANGLE-W0214` audit event is recorded per plugin,
    /// then an `ENTANGLE-I0215` summary. Afterwards loads above the ceiling
    /// fail with `ENTANGLE-E0043`.
    pub async fn apply_max_tier(
        &self,
        new: Tier,
        unload: bool,
    ) -> Result<MaxTierOutcome, Vec<LoadedPluginInfo>> {
        // The delta set and the ceiling change are one step under the
        // `plugins` write lock, which a load also holds when it re-checks the
        // ceiling and records the plugin: a load in flight either landed
        // before (it is in the delta set and unloaded below) or lands after
        // (it is refused with ENTANGLE-E0043). Concurrent calls serialise here.
        let (old, affected) = {
            let plugins = self.plugins.write();
            let old = self.max_tier_allowed();
            let affected = if new < old {
                Self::above(&plugins, new)
            } else {
                Vec::new()
            };
            if !affected.is_empty() && !unload {
                return Err(affected);
            }
            self.broker.set_max_tier_allowed(new);
            (old, affected)
        };
        let mut unloaded = Vec::new();
        for info in &affected {
            // A concurrent unload by the operator is fine: the plugin is gone
            // either way, and is still reported as affected.
            let _ = self.unload(&info.plugin).await;
            self.broker
                .audit_log()
                .record(entangle_broker::AuditEvent::PluginDisabledByCeiling {
                    plugin: info.plugin.clone(),
                    tier: info.tier,
                    old_ceiling: old,
                    new_ceiling: new,
                    at: std::time::SystemTime::now(),
                });
            unloaded.push(info.plugin.clone());
        }
        if new < old {
            self.broker
                .audit_log()
                .record(entangle_broker::AuditEvent::CeilingLowered {
                    old_ceiling: old,
                    new_ceiling: new,
                    unloaded: unloaded.len() as u32,
                    at: std::time::SystemTime::now(),
                });
        }
        Ok(MaxTierOutcome { old, new, unloaded })
    }

    /// Record that the operator cancelled a ceiling lowering
    /// (`ENTANGLE-I0216`); the ceiling is unchanged.
    pub fn record_lowering_cancelled(&self, requested: Tier) {
        self.broker
            .audit_log()
            .record(entangle_broker::AuditEvent::CeilingLoweringCancelled {
                current: self.max_tier_allowed(),
                requested,
                at: std::time::SystemTime::now(),
            });
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
