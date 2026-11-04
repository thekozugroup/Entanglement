//! The [`Kernel`] — top-level orchestrator that wires together all subsystems.

use crate::{
    errors::RuntimeError,
    lifecycle::{LifecycleEvent, LifecyclePhase},
    loader::PluginPackage,
    native::{NativeConfig, NativePlugin},
};
use entangle_broker::{
    Broker, BrokerError, BrokerPolicy, CapabilityPattern, CapabilityStatus, GrantId,
};
use entangle_host::{
    check_runtime_kind, CapabilityContext, CompiledPlugin, DeclaredRuntime, HostEngine, StreamPort,
    StreamRunResult,
};
use entangle_ipc::{Bus, Envelope, Topic};
use entangle_manifest::Runtime;
use entangle_manifest::{loader::LoadError, validate::validate, ValidatedManifest};
use entangle_observability::catalog::{self, names, PluginLabels};
use entangle_observability::Registry;
use entangle_signing::{verify_artifact, Keyring, SignatureBundle, VerificationError};
use entangle_types::{plugin_id::PluginId, tier::Tier};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Instant, SystemTime};
use tracing::Instrument as _;

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
    /// limits (spec §3.4). `native.data_dir` is the storage root for **both**
    /// runtimes: wasm plugins' storage grants are preopened from the same
    /// directories (see `entangle_host::storage`).
    pub native: NativeConfig,
    /// `[security] deny_capabilities`: capabilities the broker never grants,
    /// whatever a manifest declares (spec §4.5). A plugin declaring one still
    /// loads, without it.
    pub denied_capabilities: Vec<CapabilityPattern>,
    /// `[plugins] disabled`: plugin ids (`<publisher>/<name>@<version>`) the
    /// kernel refuses to load (`ENTANGLE-E0759`), e.g. those unloaded by a
    /// `max_tier_allowed` lowering. Updatable at run time with
    /// [`Kernel::set_disabled_plugins`].
    pub disabled_plugins: Vec<String>,
    /// The on-disk AOT compilation cache (`[runtime] aot_cache`; spec §3.3
    /// "pre-compile"): wasm components are deserialized from a verified
    /// entry instead of compiled when one exists. `None` (the default):
    /// every load compiles. A cache directory that cannot be used is
    /// logged (`ENTANGLE-E0786`) and the kernel runs without one.
    pub aot_cache: Option<crate::AotCacheConfig>,
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            max_tier_allowed: Tier::Native,
            multi_node: false,
            bus_capacity: 1024,
            native: NativeConfig::default(),
            denied_capabilities: Vec::new(),
            disabled_plugins: Vec::new(),
            aot_cache: None,
        }
    }
}

// ── internal per-plugin record ───────────────────────────────────────────────

struct LoadedRecord {
    effective_tier: Tier,
    plugin: PluginImpl,
    /// The grants a native plugin's sandbox profile was derived from (empty
    /// for wasm, whose context is re-derived from the broker per
    /// invocation). The profile is fixed at load, so once any of them is
    /// revoked the plugin is refused until it is reloaded — never run with
    /// authority the broker has withdrawn.
    sandbox_grants: Vec<entangle_broker::GrantedCapability>,
    loaded_at: Instant,
    /// Held shared by every running invocation (taken while the record is
    /// still in the map); [`Kernel::unload`] takes it exclusively after
    /// removing the record, i.e. waits for those invocations to finish.
    inflight: Arc<tokio::sync::RwLock<()>>,
}

/// A running invocation's (one-shot or stream) share of
/// [`LoadedRecord::inflight`].
type InflightToken = tokio::sync::OwnedRwLockReadGuard<()>;

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

/// Why [`Kernel::apply_max_tier`] refused to lower the ceiling. Nothing was
/// changed in either case.
#[derive(Clone, Debug)]
pub enum MaxTierRefusal {
    /// Lowering would unload these plugins and unloading was not authorised.
    NeedsUnload(Vec<LoadedPluginInfo>),
    /// Unloading was authorised for a confirmed list of plugins, but these
    /// plugins above the new ceiling are not on it (typically loaded after
    /// the operator saw the list). They are never unloaded unseen.
    Unconfirmed(Vec<LoadedPluginInfo>),
}

/// How a loaded plugin executes.
#[derive(Clone)]
enum PluginImpl {
    /// Wasm component in the shared Wasmtime engine, of either
    /// `entangle:plugin` world (one-shot `run` or `start-stream`).
    Wasm(CompiledPlugin),
    /// Native executable in a sandboxed subprocess (see [`crate::native`]).
    /// Native plugins are one-shot only.
    Native(Arc<NativePlugin>),
}

impl PluginImpl {
    /// The `entangle:plugin` world this plugin implements: `"plugin"` or
    /// `"stream-plugin"`.
    fn world(&self) -> &'static str {
        match self {
            Self::Wasm(p) => p.world(),
            Self::Native(_) => "plugin",
        }
    }
}

/// The kernel's metric state (see [`Kernel::with_metrics`]).
struct KernelMetrics {
    registry: Registry,
    /// Bounds the `plugin` label (see [`PluginLabels`]).
    labels: PluginLabels,
    /// Load time of every loaded plugin, read by the scrape-time collector.
    loaded_at: Arc<Mutex<HashMap<String, Instant>>>,
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
    /// Shared with every wasm plugin's [`CapabilityContext`], which asks it
    /// for `capability.fetch` decisions and reads the plugin's grants.
    broker: Arc<Broker>,
    keyring: Arc<RwLock<Keyring>>,
    plugins: RwLock<HashMap<PluginId, LoadedRecord>>,
    bus: Bus<LifecycleEvent>,
    /// The single topic every lifecycle event is published on. Built once so
    /// `emit` does not re-parse and re-validate the same literal each time.
    lifecycle_topic: Topic,
    /// Metrics sink; `None` until [`Kernel::with_metrics`].
    metrics: Option<KernelMetrics>,
    /// Plugin ids refused at load (`[plugins] disabled`), shared with the
    /// metric registry (see [`Kernel::disabled_plugins`]).
    disabled: DisabledPlugins,
    /// The AOT compilation cache, when configured and usable.
    aot: Option<Arc<crate::AotCache>>,
}

/// The `[plugins] disabled` set: plugin ids refused at load. Cheap to clone;
/// clones share one set, so an update through
/// [`Kernel::set_disabled_plugins`] reaches every holder (the kernel's own
/// load path and the submitter's `MetricRegistry`).
#[derive(Clone, Debug, Default)]
pub struct DisabledPlugins(Arc<RwLock<std::collections::HashSet<String>>>);

impl DisabledPlugins {
    /// A set holding `ids`.
    pub fn new(ids: impl IntoIterator<Item = String>) -> Self {
        Self(Arc::new(RwLock::new(ids.into_iter().collect())))
    }

    /// Whether `id` is disabled.
    pub fn contains(&self, id: &PluginId) -> bool {
        self.0.read().contains(&id.to_string())
    }

    /// Replace the whole set.
    pub fn replace(&self, ids: impl IntoIterator<Item = String>) {
        *self.0.write() = ids.into_iter().collect();
    }
}

impl Kernel {
    /// Construct a new kernel with the given config and trusted keyring.
    pub fn new(config: KernelConfig, keyring: Keyring) -> Result<Self, RuntimeError> {
        let policy = BrokerPolicy {
            max_tier_allowed: config.max_tier_allowed,
            multi_node: config.multi_node,
            peer_allowlist_populated: false,
            denied_capabilities: config.denied_capabilities.clone(),
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
        let aot = config
            .aot_cache
            .clone()
            .and_then(|cfg| match crate::AotCache::open(cfg) {
                Ok(cache) => Some(Arc::new(cache)),
                Err(e) => {
                    tracing::warn!(error = %e, "AOT compilation cache disabled; every load compiles");
                    None
                }
            });
        Ok(Self {
            aot,
            bus: Bus::new(config.bus_capacity),
            lifecycle_topic: Topic::new(LIFECYCLE_TOPIC).expect("static topic is valid"),
            broker: Arc::new(Broker::new(policy)),
            engine,
            keyring: Arc::new(RwLock::new(keyring)),
            plugins: RwLock::new(HashMap::new()),
            disabled: DisabledPlugins::new(config.disabled_plugins.iter().cloned()),
            config,
            metrics: None,
        })
    }

    /// Replace the set of plugin ids refused at load (`[plugins] disabled`).
    ///
    /// Already-loaded plugins are not unloaded; this only gates later loads.
    pub fn set_disabled_plugins(&self, ids: impl IntoIterator<Item = String>) {
        self.disabled.replace(ids);
    }

    /// Whether `[plugins] disabled` currently names `id`.
    pub fn is_plugin_disabled(&self, id: &PluginId) -> bool {
        self.disabled.contains(id)
    }

    /// The live `[plugins] disabled` set, shared: later
    /// [`Kernel::set_disabled_plugins`] calls are seen through it. Give it to
    /// a [`crate::MetricRegistry`] so metric packages honour the list too.
    pub fn disabled_plugins(&self) -> DisabledPlugins {
        self.disabled.clone()
    }

    /// Record this kernel's activity into `registry`.
    ///
    /// Records plugin invocations (count, duration, errors by code class),
    /// capability grants and denials (through the broker), the loaded-plugin
    /// count and per-plugin uptime. The `plugin` label is bounded: the first
    /// [`catalog::PLUGIN_LABEL_LIMIT`] distinct plugin ids get their own
    /// series, later ones fold into `other`.
    #[must_use]
    pub fn with_metrics(self, registry: Registry) -> Self {
        if let Some(aot) = &self.aot {
            aot.attach_metrics(registry.clone());
        }
        let labels = PluginLabels::new();
        let loaded_at: Arc<Mutex<HashMap<String, Instant>>> = Arc::default();
        {
            let (labels, loaded_at) = (labels.clone(), Arc::clone(&loaded_at));
            registry.register_collector(move |r| {
                let loaded = loaded_at.lock();
                r.set_gauge(
                    names::PLUGINS_LOADED,
                    "Plugins currently loaded",
                    &[],
                    loaded.len() as f64,
                );
                // Rebuild so series for unloaded plugins disappear.
                r.clear_family(names::PLUGIN_UPTIME);
                for (id, since) in loaded.iter() {
                    let label = labels.label(id);
                    if label == catalog::OTHER_PLUGIN {
                        continue;
                    }
                    r.set_gauge(
                        names::PLUGIN_UPTIME,
                        "Seconds since the plugin was loaded",
                        &[("plugin", &label)],
                        since.elapsed().as_secs_f64(),
                    );
                }
            });
        }
        // The broker is shared only once plugins load; until then this is
        // the sole handle. A kernel with plugins loaded keeps its broker
        // (and records broker metrics nowhere) rather than splitting it.
        let broker = match Arc::try_unwrap(self.broker) {
            Ok(b) => Arc::new(b.with_metrics(registry.clone())),
            Err(shared) => {
                tracing::warn!("Kernel::with_metrics after plugins were loaded: broker metrics are not recorded");
                shared
            }
        };
        Self {
            broker,
            metrics: Some(KernelMetrics {
                registry,
                labels,
                loaded_at,
            }),
            ..self
        }
    }

    /// The AOT compilation cache in use, if any (the daemon's maintenance
    /// loop garbage-collects it).
    pub fn aot_cache(&self) -> Option<Arc<crate::AotCache>> {
        self.aot.clone()
    }

    /// Access the capability broker.
    pub fn broker(&self) -> &Broker {
        &self.broker
    }

    /// Every declared capability of a loaded plugin and where it stands
    /// (granted, denied by policy, revoked) — `entangle perms list`.
    /// `None` when the plugin is not loaded.
    pub fn capability_report(&self, plugin: &PluginId) -> Option<Vec<CapabilityStatus>> {
        self.broker.capability_report(plugin)
    }

    /// Revoke a loaded plugin's capability by manifest key (`net.wan`,
    /// `storage.local`, ...) — `entangle perms revoke` (spec §4.6). Takes
    /// effect at once for `capability.fetch` and for a wasm plugin's network
    /// (new sockets and lookups are refused, and an invocation running on a
    /// revoked network grant is stopped with `ENTANGLE-E0511`), and
    /// from the next invocation for wasm storage. A native plugin whose
    /// sandbox was derived from a revoked grant is refused
    /// (`ENTANGLE-E0125`) until it is reloaded. Returns the grants withdrawn.
    pub fn revoke_capability(
        &self,
        plugin: &PluginId,
        key: &str,
    ) -> Result<Vec<GrantId>, RuntimeError> {
        Ok(self.broker.revoke(plugin, key)?)
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
    /// 3. Register the plugin with the capability broker and resolve its
    ///    declared capabilities (spec §4.5, [`Broker::grant_declared`]): each
    ///    is granted, or — when the operator's `deny_capabilities` policy
    ///    refuses it — denied, audited and logged, and the plugin loads
    ///    without it.
    /// 4. Wasm: compile the artifact with the host engine and realise the
    ///    grants once (creating storage directories) so a grant that cannot
    ///    be realised fails the load. Native: derive the sandbox from the
    ///    grants, plan it (refusing when none is available), and stage the
    ///    verified bytes (see [`crate::native`]). On failure the broker
    ///    registration — and with it every grant — is rolled back; no
    ///    partial state remains.
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

        // Operator-disabled plugins (`[plugins] disabled`) never load, whatever
        // their signature says; refusing needs no verified manifest.
        if self.is_plugin_disabled(&plugin_id) {
            return Err(RuntimeError::PluginDisabled(plugin_id));
        }

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
        // ── Step 3: Broker ───────────────────────────────────────────────────
        // register_plugin takes ownership of ValidatedManifest (not Clone).
        self.broker.register_plugin(manifest)?;
        self.emit(&plugin_id, effective_tier, LifecyclePhase::Registered);

        // ── Step 4: Capabilities, then host / native sandbox ─────────────────
        // On failure, roll back the broker registration (which also releases
        // any grants, audited) so no partial state remains.
        let plugin = match self.resolve_capabilities(&plugin_id) {
            Err(e) => Err(e),
            Ok(grants) => match runtime {
                Runtime::Wasm => self
                    .prepare_wasm(&plugin_id, &pkg, effective_tier)
                    .await
                    .map(|p| (p, Vec::new())),
                Runtime::Native => self
                    .prepare_native(&plugin_id, &pkg, &grants)
                    .map(|n| (PluginImpl::Native(Arc::new(n)), grants)),
            },
        };
        let (plugin, sandbox_grants) = match plugin {
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
                    let loaded_at = Instant::now();
                    slot.insert(LoadedRecord {
                        effective_tier,
                        plugin,
                        sandbox_grants,
                        loaded_at,
                        inflight: Arc::new(tokio::sync::RwLock::new(())),
                    });
                    if let Some(m) = &self.metrics {
                        m.loaded_at.lock().insert(plugin_id.to_string(), loaded_at);
                    }
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
        let started = Instant::now();
        let span = tracing::info_span!(
            "plugin.invoke",
            plugin = %plugin_id,
            world = "plugin",
            input_bytes = input.len() as u64,
        );
        let result = self
            .invoke_inner(plugin_id, input, timeout_ms)
            .instrument(span)
            .await;
        if let Some(m) = &self.metrics {
            // A call for an id that is not loaded must not mint a label
            // value: it is filed under `unknown`.
            let label = match &result {
                Err(RuntimeError::NotLoaded(_)) => "unknown".to_owned(),
                _ => m.labels.label(&plugin_id.to_string()),
            };
            let error = result.as_ref().err().map(ToString::to_string);
            catalog::plugin_invocation(
                &m.registry,
                &label,
                error.as_deref(),
                started.elapsed().as_secs_f64(),
            );
        }
        result
    }

    async fn invoke_inner(
        &self,
        plugin_id: &PluginId,
        input: &[u8],
        timeout_ms: u64,
    ) -> Result<Vec<u8>, RuntimeError> {
        // Acquire the read lock, clone what we need, then release it before
        // the async call so we don't hold a lock across an .await point.
        // The in-flight token is held until this invocation returns, so an
        // unload (or a ceiling lowering) drains it before unregistering.
        let (plugin, effective_tier, _inflight) = self.record(plugin_id)?;
        if let PluginImpl::Wasm(CompiledPlugin::Stream(_)) = plugin {
            return Err(RuntimeError::WrongWorld {
                plugin: plugin_id.clone(),
                expected: "plugin",
                actual: plugin.world(),
            });
        }

        self.emit(plugin_id, effective_tier, LifecyclePhase::Activated);
        // The plugin call is contained (spec §2.1, `entangle_core::fault`):
        // a panic in host code it reaches — outside the broker's critical
        // sections — fails this call, whose store and instance are discarded
        // with it, instead of ending the daemon.
        let call = async {
            match plugin {
                PluginImpl::Wasm(CompiledPlugin::OneShot(p)) => p
                    .run_one_shot(&self.engine, input, timeout_ms)
                    .await
                    .map(|r| r.output)
                    .map_err(RuntimeError::from),
                PluginImpl::Wasm(CompiledPlugin::Stream(_)) => {
                    unreachable!("stream plugins are refused above")
                }
                PluginImpl::Native(n) => n
                    .invoke(input, timeout_ms)
                    .await
                    .map_err(RuntimeError::from),
            }
        };
        let result = entangle_core::fault::contain(call)
            .await
            .unwrap_or_else(|p| {
                Err(RuntimeError::HostPanicked {
                    plugin: plugin_id.clone(),
                    message: p.message,
                })
            });
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

    /// Resolve the plugin's declared capabilities through the broker
    /// (spec §4.5): the standing grants both runtimes realise. Capabilities
    /// the operator's policy denies are audited by the broker and logged
    /// here; the plugin loads without them.
    fn resolve_capabilities(
        &self,
        plugin_id: &PluginId,
    ) -> Result<Vec<entangle_broker::GrantedCapability>, RuntimeError> {
        let resolution = self.broker.grant_declared(plugin_id)?;
        for (cap, why) in &resolution.denied {
            tracing::warn!(plugin = %plugin_id, capability = %cap.key(), reason = %why, "declared capability denied; plugin loads without it");
        }
        Ok(resolution.granted)
    }

    /// Compile the component (of either `entangle:plugin` world), attach the
    /// broker and storage root, and realise the standing grants once so an
    /// unrealisable grant (no storage root, a symlinked scope) fails the load
    /// instead of every invocation or stream.
    async fn prepare_wasm(
        &self,
        plugin_id: &PluginId,
        pkg: &PluginPackage,
        effective_tier: Tier,
    ) -> Result<PluginImpl, RuntimeError> {
        let mut ctx = CapabilityContext::new(Arc::clone(&self.broker));
        if let Some(root) = &self.config.native.data_dir {
            ctx = ctx.with_storage_root(root);
        }
        // Either world: a stream plugin's instances realise exactly the
        // grants a one-shot plugin's do (preopens, socket rules, pinned
        // names, live revocation).
        let (plugin, lookup) = CompiledPlugin::from_bytes_cached(
            &self.engine,
            &pkg.bytes,
            plugin_id.clone(),
            effective_tier,
            self.aot.as_deref(),
        )?;
        if let Some(lookup) = lookup {
            tracing::debug!(plugin = %plugin_id, ?lookup, "AOT cache");
        }
        let plugin = plugin.with_capabilities(ctx);
        plugin.realise_capabilities().await?;
        Ok(PluginImpl::Wasm(plugin))
    }

    /// Derive the sandbox from the standing grants and stage the verified
    /// binary.
    fn prepare_native(
        &self,
        plugin_id: &PluginId,
        pkg: &PluginPackage,
        grants: &[entangle_broker::GrantedCapability],
    ) -> Result<NativePlugin, RuntimeError> {
        Ok(NativePlugin::prepare(
            plugin_id,
            &pkg.bytes,
            Some(&pkg.dir),
            grants,
            &self.config.native,
        )?)
    }

    /// Run a loaded `stream-plugin` component's `start-stream(input)` with
    /// `port` attached, until the plugin returns (spec §7.1).
    ///
    /// Chunks the plugin yields, and input it reads, flow through `port`;
    /// the caller drives the other end. Bounded by `timeout_ms` exactly as a
    /// one-shot invocation is, and given exactly its capabilities: the
    /// stream's instance realises the plugin's broker grants as they stand
    /// when it starts, and a network grant withdrawn while it runs stops it
    /// (`ENTANGLE-E0511`). A one-shot plugin is [`RuntimeError::WrongWorld`].
    ///
    /// Recorded like a one-shot invocation: a `plugin.invoke` span (with
    /// `world = "stream-plugin"`), and — with [`Kernel::with_metrics`] —
    /// `entangle_plugin_streams_total{plugin, outcome}` (`ok`, `error`, or
    /// `cancelled` when the stream is torn down before the plugin returns:
    /// the future is dropped, the plugin fails after `port` was closed under
    /// it — a refused chunk, a closed input — or it hits its timeout),
    /// `entangle_plugin_stream_duration_seconds{plugin}` and, on failure,
    /// `entangle_plugin_errors_total{plugin, class}`. The `plugin` label is
    /// bounded exactly as for one-shot invocations.
    pub async fn invoke_stream(
        &self,
        plugin_id: &PluginId,
        input: &[u8],
        port: StreamPort,
        timeout_ms: u64,
    ) -> Result<StreamRunResult, RuntimeError> {
        let span = tracing::info_span!(
            "plugin.invoke",
            plugin = %plugin_id,
            world = "stream-plugin",
            input_bytes = input.len() as u64,
        );
        // Records the outcome on every path, including the future being
        // dropped mid-stream (`cancelled`).
        let mut recorder = StreamRecorder {
            kernel: self,
            plugin_id,
            started: Instant::now(),
            done: false,
        };
        // The executor tears a stream down under its plugin (refuses the
        // pending chunk, closes the input) and only then drops this future:
        // the plugin's resulting failure is the teardown, not its own.
        let teardown = port.teardown_signal();
        let result = self
            .invoke_stream_inner(plugin_id, input, port, timeout_ms)
            .instrument(span)
            .await;
        recorder.finish(&result, teardown.torn_down());
        result
    }

    async fn invoke_stream_inner(
        &self,
        plugin_id: &PluginId,
        input: &[u8],
        port: StreamPort,
        timeout_ms: u64,
    ) -> Result<StreamRunResult, RuntimeError> {
        // The in-flight token is held for the whole stream, exactly as for a
        // one-shot invocation: an unload, and so a ceiling lowering that
        // affects this plugin, waits for the stream to end (it returns, times
        // out, or its future is dropped) before releasing the plugin's grants.
        // It is declared before the `Idled` guard, so it is released after
        // `Idled` is published.
        let (plugin, effective_tier, _inflight) = self.record(plugin_id)?;
        let PluginImpl::Wasm(CompiledPlugin::Stream(plugin)) = plugin else {
            return Err(RuntimeError::WrongWorld {
                plugin: plugin_id.clone(),
                expected: "stream-plugin",
                actual: plugin.world(),
            });
        };

        self.emit(plugin_id, effective_tier, LifecyclePhase::Activated);
        // A stream routinely ends before the plugin returns (cancel, PeerLost,
        // a size cap): the caller then drops this future. A drop guard
        // publishes `Idled` on that path as well as on normal return.
        let _idle = IdleOnDrop {
            kernel: self,
            plugin_id,
            effective_tier,
        };
        // Contained exactly like a one-shot call (spec §2.1).
        let result = entangle_core::fault::contain(plugin.run_stream(
            &self.engine,
            input,
            port,
            timeout_ms,
            entangle_host::state::ResourceLimits::default(),
        ))
        .await
        .map_err(|p| RuntimeError::HostPanicked {
            plugin: plugin_id.clone(),
            message: p.message,
        })?;
        Ok(result?)
    }

    /// The `entangle:plugin` world a loaded plugin implements: `"plugin"`
    /// (one-shot `run`) or `"stream-plugin"` (`start-stream`).
    pub fn plugin_world(&self, plugin_id: &PluginId) -> Option<&'static str> {
        self.plugins
            .read()
            .get(plugin_id)
            .map(|record| record.plugin.world())
    }

    /// Clone a loaded plugin's implementation and tier and take its
    /// in-flight token, releasing the lock before any `.await`. A plugin
    /// above the ceiling in force (lowered since it loaded) is refused
    /// (`ENTANGLE-E0043`), and a native plugin whose sandbox was derived
    /// from a grant since revoked is refused (`ENTANGLE-E0125`) until it is
    /// reloaded.
    ///
    /// The caller holds the token for as long as the plugin's code runs
    /// (a one-shot call or a whole stream). It is taken while the record is
    /// still in the map, so an unload that removes the record afterwards
    /// waits for the caller to drop it (taking it never fails here: unload
    /// only waits for the token after the record is gone).
    fn record(
        &self,
        plugin_id: &PluginId,
    ) -> Result<(PluginImpl, Tier, InflightToken), RuntimeError> {
        let plugins = self.plugins.read();
        let record = plugins
            .get(plugin_id)
            .ok_or_else(|| RuntimeError::NotLoaded(plugin_id.clone()))?;
        // Above a ceiling lowered since it loaded (it is waiting to be
        // drained and unloaded): suspended, nothing new starts.
        self.broker
            .check_tier(record.effective_tier)
            .map_err(BrokerError::from)?;
        // A native sandbox cannot shed a revoked grant: refuse instead.
        if let Some(g) = record
            .sandbox_grants
            .iter()
            .find(|g| !self.broker.is_live(plugin_id, g.grant_id))
        {
            return Err(RuntimeError::Broker(BrokerError::CapabilityRevoked {
                plugin: plugin_id.clone(),
                capability: g.kind.key().into_owned(),
            }));
        }
        let token = record
            .inflight
            .clone()
            .try_read_owned()
            .map_err(|_| RuntimeError::NotLoaded(plugin_id.clone()))?;
        Ok((record.plugin.clone(), record.effective_tier, token))
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

    /// Unload a currently-loaded plugin, draining it first.
    ///
    /// From the moment this is called new invocations and streams fail with
    /// [`RuntimeError::NotLoaded`]; invocations already running, one-shot
    /// ([`Kernel::invoke`]) and streaming ([`Kernel::invoke_stream`]) alike,
    /// are waited for (each is bounded by its own timeout, and a stream also
    /// ends when its caller drops it), so the plugin's broker
    /// grants are not released while its code still runs (spec §9.4.1 step 4:
    /// "gracefully drained, then unloaded"). Then de-registers from the
    /// broker and emits a [`LifecyclePhase::Unloaded`] event.
    pub async fn unload(&self, plugin: &PluginId) -> Result<(), RuntimeError> {
        let record = self
            .plugins
            .write()
            .remove(plugin)
            .ok_or_else(|| RuntimeError::NotLoaded(plugin.clone()))?;
        if let Some(m) = &self.metrics {
            m.loaded_at.lock().remove(&plugin.to_string());
        }
        let _drained = record.inflight.write().await;
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
    /// affected plugins are returned in [`MaxTierRefusal::NeedsUnload`] so the
    /// caller can prompt. With `confirmed` (the list the operator was shown
    /// and agreed to), a delta set containing any other plugin is refused
    /// with [`MaxTierRefusal::Unconfirmed`] and nothing changes.
    ///
    /// Once the new ceiling is set, every affected plugin is suspended at
    /// once, before its turn to be unloaded comes: new invocations and
    /// streams are refused (`ENTANGLE-E0043`, or `NotLoaded` once its unload
    /// started), and its capabilities stop exactly as on a revocation
    /// (`Kernel::revoke_capability`) — `capability.fetch` is refused
    /// (`ENTANGLE-E0127`), new sockets and name lookups are refused, and an
    /// invocation or stream running on a network grant is stopped
    /// (`ENTANGLE-E0511`); an open storage directory stays open until the
    /// invocation ends. The unload goes through [`Kernel::unload`], which
    /// drains invocations still running (including active streams) and then
    /// releases the broker grants (audited); only then is the
    /// plugin's `ENTANGLE-W0214` audit event recorded (one per plugin),
    /// then an `ENTANGLE-I0215` summary. Afterwards loads above the ceiling
    /// fail with `ENTANGLE-E0043`. Raising records `ENTANGLE-I0217`; applying
    /// the ceiling already in force records nothing.
    pub async fn apply_max_tier(
        &self,
        new: Tier,
        unload: bool,
        confirmed: Option<&[PluginId]>,
    ) -> Result<MaxTierOutcome, MaxTierRefusal> {
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
                return Err(MaxTierRefusal::NeedsUnload(affected));
            }
            if let Some(confirmed) = confirmed {
                let unseen: Vec<LoadedPluginInfo> = affected
                    .iter()
                    .filter(|a| !confirmed.contains(&a.plugin))
                    .cloned()
                    .collect();
                if !unseen.is_empty() {
                    return Err(MaxTierRefusal::Unconfirmed(unseen));
                }
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
        } else if new > old {
            self.broker
                .audit_log()
                .record(entangle_broker::AuditEvent::CeilingRaised {
                    old_ceiling: old,
                    new_ceiling: new,
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

/// Records one stream-plugin invocation's metrics exactly once: from
/// [`StreamRecorder::finish`] when the invocation returns, or as `cancelled`
/// when its future is dropped first.
struct StreamRecorder<'a> {
    kernel: &'a Kernel,
    plugin_id: &'a PluginId,
    started: Instant,
    done: bool,
}

impl StreamRecorder<'_> {
    /// `torn_down`: the guest saw its stream closed under it (see
    /// [`entangle_host::TeardownSignal`]). A failure after that — like the
    /// stream's wall-clock timeout — is `cancelled`, not a plugin error.
    fn finish(&mut self, result: &Result<StreamRunResult, RuntimeError>, torn_down: bool) {
        self.done = true;
        let Some(m) = &self.kernel.metrics else {
            return;
        };
        // An id that is not loaded must not mint a label value.
        let label = match result {
            Err(RuntimeError::NotLoaded(_)) => "unknown".to_owned(),
            _ => m.labels.label(&self.plugin_id.to_string()),
        };
        let message = match result {
            Ok(_) => None,
            Err(RuntimeError::Host(entangle_host::HostError::Timeout(_))) => None,
            Err(_) if torn_down => None,
            Err(e) => Some(e.to_string()),
        };
        let end = match (&message, result) {
            (None, Ok(_)) => catalog::StreamEnd::Ok,
            (None, Err(_)) => catalog::StreamEnd::Cancelled,
            (Some(message), _) => catalog::StreamEnd::Err(message),
        };
        catalog::plugin_stream(
            &m.registry,
            &label,
            end,
            self.started.elapsed().as_secs_f64(),
        );
    }
}

impl Drop for StreamRecorder<'_> {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        if let Some(m) = &self.kernel.metrics {
            catalog::plugin_stream(
                &m.registry,
                &m.labels.label(&self.plugin_id.to_string()),
                catalog::StreamEnd::Cancelled,
                self.started.elapsed().as_secs_f64(),
            );
        }
    }
}

/// Publishes [`LifecyclePhase::Idled`] when dropped, so a stream future that
/// is dropped mid-run still balances its `Activated`.
struct IdleOnDrop<'a> {
    kernel: &'a Kernel,
    plugin_id: &'a PluginId,
    effective_tier: Tier,
}

impl Drop for IdleOnDrop<'_> {
    fn drop(&mut self) {
        self.kernel
            .emit(self.plugin_id, self.effective_tier, LifecyclePhase::Idled);
    }
}
